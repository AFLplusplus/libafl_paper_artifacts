use libafl::{
    corpus::Corpus,
    inputs::Input,
    stages::Stage,
    state::{HasCorpus, HasMetadata, HasSolutions},
    Error,
};

use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::Write,
    marker::PhantomData,
    path::{Path, PathBuf},
};

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct FuzzbenchDumpMetadata {
    pub last_queue: usize,
    pub last_crash: usize,
}

libafl::impl_serdeany!(FuzzbenchDumpMetadata);

pub struct FuzzbenchDumpStage<CB, E, EM, I, S, Z>
where
    CB: FnMut(&I) -> Vec<u8>,
    I: Input,
    S: HasSolutions<I> + HasCorpus<I> + HasMetadata,
{
    crashes_dir: PathBuf,
    queue_dir: PathBuf,
    to_bytes: CB,
    phantom: PhantomData<(E, EM, I, S, Z)>,
}

impl<CB, E, EM, I, S, Z> Stage<E, EM, S, Z> for FuzzbenchDumpStage<CB, E, EM, I, S, Z>
where
    CB: FnMut(&I) -> Vec<u8>,
    I: Input,
    S: HasSolutions<I> + HasCorpus<I> + HasMetadata,
{
    #[inline]
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        _manager: &mut EM,
        _corpus_idx: usize,
    ) -> Result<(), Error> {
        let meta = state
            .metadata()
            .get::<FuzzbenchDumpMetadata>()
            .map(|m| m.clone())
            .unwrap_or_else(|| FuzzbenchDumpMetadata::default());

        let queue_count = state.corpus().count();
        let crashes_count = state.solutions().count();

        for i in meta.last_queue..queue_count {
            let mut testcase = state.corpus().get(i)?.borrow_mut();
            let input = testcase.load_input()?;
            let bytes = (self.to_bytes)(input);

            let fname = self.queue_dir.join(format!("id_{}", i));
            let mut f = File::create(fname).expect("Unable to open file");
            drop(f.write(&bytes));
        }

        for i in meta.last_crash..crashes_count {
            let mut testcase = state.solutions().get(i)?.borrow_mut();
            let input = testcase.load_input()?;
            let bytes = (self.to_bytes)(input);

            let fname = self.crashes_dir.join(format!("id_{}", i));
            let mut f = File::create(fname).expect("Unable to open file");
            drop(f.write(&bytes));
        }

        state.add_metadata(FuzzbenchDumpMetadata {
            last_queue: queue_count,
            last_crash: crashes_count,
        });

        Ok(())
    }
}

impl<CB, E, EM, I, S, Z> FuzzbenchDumpStage<CB, E, EM, I, S, Z>
where
    CB: FnMut(&I) -> Vec<u8>,
    I: Input,
    S: HasSolutions<I> + HasCorpus<I> + HasMetadata,
{
    #[must_use]
    pub fn new(to_bytes: CB, report_dir: &Path) -> Self {
        let mut crashes_dir = report_dir.to_path_buf();
        crashes_dir.push("crashes");
        if fs::create_dir(&crashes_dir).is_err() {
            println!("Crashes dir at {:?} already exists.", &crashes_dir);
            if !crashes_dir.is_dir() {
                panic!(
                    "Crashes dir at {:?} is not a valid directory!",
                    &crashes_dir
                );
            }
        }
        let mut queue_dir = report_dir.to_path_buf();
        queue_dir.push("queue");
        if fs::create_dir(&queue_dir).is_err() {
            println!("Queue dir at {:?} already exists.", &queue_dir);
            if !queue_dir.is_dir() {
                panic!("Queue dir at {:?} is not a valid directory!", &queue_dir);
            }
        }
        Self {
            to_bytes,
            crashes_dir,
            queue_dir,
            phantom: PhantomData,
        }
    }
}
