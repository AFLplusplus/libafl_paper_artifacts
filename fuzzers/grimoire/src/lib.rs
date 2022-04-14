//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
//! In this example, you will see the use of the `launcher` feature.
//! The `launcher` will spawn new processes for each cpu core.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use clap::{App, Arg};
use core::time::Duration;
#[cfg(unix)]
use nix::{self, unistd::dup};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    env,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
};

use libafl::{
    bolts::{
        current_nanos,
        os::dup2,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
        AsSlice,
    },
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::SimpleRestartingEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{Generator, NautilusContext, NautilusGenerator},
    inputs::{GeneralizedInput, HasBytesVec, HasTargetBytes, Input},
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations, scheduled::StdScheduledMutator, GrimoireExtensionMutator,
        GrimoireRandomDeleteMutator, GrimoireRecursiveReplacementMutator,
        GrimoireStringReplacementMutator, I2SRandReplace, Tokens,
    },
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{mutational::StdMutationalStage, GeneralizationStage, TracingStage},
    state::{HasCorpus, HasMetadata, StdState},
    Error, Evaluator,
};

use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, CmpLogObserver, CMPLOG_MAP, EDGES_MAP,
    MAX_EDGES_NUM,
};

#[cfg(target_os = "linux")]
use libafl_targets::autotokens;

/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub fn libafl_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    let res = match App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("AFLplusplus team")
        .about("LibAFL-based fuzzer for Fuzzbench")
        .arg(
            Arg::new("out")
                .short('o')
                .long("output")
                .help("The directory to place finds in ('corpus')")
                .takes_value(true),
        )
        .arg(
            Arg::new("report")
                .short('r')
                .long("report")
                .help("The directory to place dumped testcases ('corpus')")
                .takes_value(true),
        )
        .arg(
            Arg::new("grammar")
                .short('g')
                .long("grammar")
                .help("The grammar model")
                .takes_value(true),
        )
        .arg(
            Arg::new("tokens")
                .short('x')
                .long("tokens")
                .help("A file to read tokens from, to be used during fuzzing")
                .takes_value(true),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Timeout for each individual execution, in milliseconds")
                .default_value("12000"),
        )
        .arg(
            Arg::new("dump")
                .short('d')
                .long("dump")
                .help("Dump serialized testcases to bytes")
                .takes_value(false),
        )
        .arg(Arg::new("remaining").multiple_values(true))
        .try_get_matches()
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, [-x dictionary] -o corpus_dir -g grammar.json\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err.info,
            );
            return;
        }
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    if let Some(filenames) = res.values_of("remaining") {
        let filenames: Vec<&str> = filenames.collect();
        if !filenames.is_empty() {
            run_testcases(&filenames);
            return;
        }
    }

    let grammar_path = PathBuf::from(
        res.value_of("grammar")
            .expect("The --grammar parameter is missing")
            .to_string(),
    );
    if !grammar_path.is_file() {
        println!("{:?} is not a valid file!", &grammar_path);
        return;
    }
    let context = NautilusContext::from_file(64, grammar_path);

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let mut out_dir = PathBuf::from(
        res.value_of("out")
            .expect("The --output parameter is missing")
            .to_string(),
    );
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }
    let mut initial_dir = out_dir.clone();
    initial_dir.push("initial");
    fs::create_dir_all(&initial_dir).unwrap();
    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let report_dir = PathBuf::from(
        res.value_of("report")
            .expect("The --report parameter is missing")
            .to_string(),
    );
    if fs::create_dir(&report_dir).is_err() {
        println!("Report dir at {:?} already exists.", &report_dir);
        if !report_dir.is_dir() {
            println!("Report dir at {:?} is not a valid directory!", &report_dir);
            return;
        }
    }

    let tokens = res.value_of("tokens").map(PathBuf::from);

    let timeout = Duration::from_millis(
        res.value_of("timeout")
            .unwrap()
            .to_string()
            .parse()
            .expect("Could not parse timeout in milliseconds"),
    );

    fuzz(
        initial_dir,
        out_dir,
        crashes,
        report_dir,
        context,
        tokens,
        timeout,
    )
    .expect("An error occurred while fuzzing");
}

fn run_testcases(filenames: &[&str]) {
    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if libfuzzer_initialize(&args) == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1")
    }

    println!(
        "You are not fuzzing, just executing {} testcases",
        filenames.len()
    );
    for fname in filenames {
        println!("Executing {}", fname);

        let input = GeneralizedInput::from_file(fname).expect("no file found");

        let target_bytes = input.target_bytes();
        let mut bytes = target_bytes.as_slice().to_vec();
        if *bytes.last().unwrap() != 0 {
            bytes.push(0);
        }
        unsafe {
            println!("Testcase: {}", std::str::from_utf8_unchecked(&bytes));
        }
        libfuzzer_test_one_input(&bytes);
    }
}

/// The actual fuzzer
fn fuzz(
    initial_dir: PathBuf,
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    report_dir: PathBuf,
    context: NautilusContext,
    tokenfile: Option<PathBuf>,
    timeout: Duration,
) -> Result<(), Error> {
    #[cfg(unix)]
    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };
    #[cfg(unix)]
    let file_null = File::open("/dev/null")?;

    // 'While the monitor are state, they are usually used in the broker - which is likely never restarted
    let monitor = SimpleMonitor::new(|s| {
        #[cfg(unix)]
        writeln!(&mut stdout_cpy, "{}", s).unwrap();
        #[cfg(windows)]
        println!("{}", s);
    });

    let mut generator = NautilusGenerator::new(&context);

    let mut initial_inputs = vec![];
    let mut bytes = vec![];
    for i in 0..4096 {
        //for i in 0..1 {
        let nautilus = generator.generate(&mut ()).unwrap();
        nautilus.unparse(&context, &mut bytes);

        let mut file = fs::File::create(&initial_dir.join(format!("id_{}", i))).unwrap();
        file.write_all(&bytes).unwrap();

        let input = GeneralizedInput::new(bytes.clone());
        initial_inputs.push(input);
    }

    // We need a shared map to store our state before a crash.
    // This way, we are able to continue fuzzing afterwards.
    let mut shmem_provider = StdShMemProvider::new()?;

    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {}", err);
            }
        },
    };

    // Create an observation channel using the coverage map
    let edges = unsafe { &mut EDGES_MAP[0..MAX_EDGES_NUM] };
    let edges_observer = HitcountsMapObserver::new(StdMapObserver::new("edges", edges));

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let cmplog = unsafe { &mut CMPLOG_MAP };
    let cmplog_observer = CmpLogObserver::new("cmplog", cmplog, true);

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&edges_observer);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, true),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new_with_observer(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let objective = CrashFeedback::new();

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            CachedOnDiskCorpus::new(corpus_dir, 4096).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // States of the feedbacks.
            // They are the data related to the feedbacks that you want to persist in the State.
            tuple_list!(feedback_state),
        )
    });

    // Read tokens
    if state.metadata().get::<Tokens>().is_none() {
        let mut toks = Tokens::default();
        if let Some(tokenfile) = &tokenfile {
            toks.add_from_file(tokenfile)?;
        }
        #[cfg(target_os = "linux")]
        {
            toks += autotokens()?;
        }

        if !toks.is_empty() {
            state.add_metadata(toks);
        }
    }

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let generalization = GeneralizationStage::new(&edges_observer);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &GeneralizedInput| {
        /*use libafl::inputs::generalized::GeneralizedItem;
        if input.grimoire_mutated {
            if let Some(gen) = input.generalized() {
                print!(">> ");
                for e in gen {
                    match e {
                        GeneralizedItem::Bytes(b) => print!("`{}`", unsafe { std::str::from_utf8_unchecked(&b) }),
                        GeneralizedItem::Gap => print!(" <GAP> "),
                    }
                }
                print!("\n");
            }
            let bytes = input.generalized_to_bytes();
            println!("@@ {}", unsafe { std::str::from_utf8_unchecked(&bytes) });
        }*/
        let target_bytes = input.target_bytes();
        let bytes = target_bytes.as_slice();
        libfuzzer_test_one_input(&bytes);
        ExitKind::Ok
    };

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor = TimeoutExecutor::new(
        InProcessExecutor::new(
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )?,
        timeout,
    );

    let mut tracing_harness = |input: &GeneralizedInput| {
        let target_bytes = input.target_bytes();
        let bytes = target_bytes.as_slice();
        libfuzzer_test_one_input(&bytes);
        ExitKind::Ok
    };

    // Setup a tracing stage in which we log comparisons
    let tracing = TracingStage::new(TimeoutExecutor::new(
        InProcessExecutor::new(
            &mut tracing_harness,
            tuple_list!(cmplog_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )?,
        // Give it more time!
        timeout * 10,
    ));

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if libfuzzer_initialize(&args) == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1")
    }

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        for input in &initial_inputs {
            fuzzer
                .add_input(&mut state, &mut executor, &mut mgr, input.clone())
                .unwrap();
        }
    }

    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::with_max_stack_pow(havoc_mutations(), 2);
    let grimoire_mutator = StdScheduledMutator::with_max_stack_pow(
        tuple_list!(
            GrimoireExtensionMutator::new(),
            GrimoireRecursiveReplacementMutator::new(),
            GrimoireStringReplacementMutator::new(),
            // give more probability to avoid large inputs
            GrimoireRandomDeleteMutator::new(),
            GrimoireRandomDeleteMutator::new(),
        ),
        3,
    );

    let fuzzbench = fuzzbench_util::FuzzbenchDumpStage::new(
        |input: &GeneralizedInput| {
            if input.generalized().is_some() {
                input.generalized_to_bytes()
            } else {
                input.bytes().to_vec()
            }
        },
        &report_dir,
    );

    let mut stages = tuple_list!(
        fuzzbench,
        generalization,
        tracing,
        i2s,
        StdMutationalStage::new(mutator),
        StdMutationalStage::new(grimoire_mutator)
    );

    // Remove target ouput (logs still survive)
    #[cfg(unix)]
    {
        let null_fd = file_null.as_raw_fd();
        dup2(null_fd, io::stdout().as_raw_fd())?;
        dup2(null_fd, io::stderr().as_raw_fd())?;
    }

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    Ok(())
}
