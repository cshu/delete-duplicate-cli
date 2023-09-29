#![allow(clippy::print_literal)]
#![allow(clippy::needless_return)]
#![allow(dropping_references)]
#![allow(clippy::assertions_on_constants)]

use crabrs::*;
use log::*;
use std::path::Path;
use std::path::PathBuf;
use std::process::*;
use std::*;
use walkdir::WalkDir;

#[macro_use(defer)]
extern crate scopeguard;

fn main() -> ExitCode {
    env::set_var("RUST_BACKTRACE", "1"); //? not 100% sure this has 0 impact on performance? Maybe setting via command line instead of hardcoding is better?
                                         //env::set_var("RUST_LIB_BACKTRACE", "1");//? this line is useless?
                                         ////
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info"); //note this line must be above logger init.
    }
    env_logger::init();
    fn the_end() {
        if std::thread::panicking() {
            info!("{}", "PANICKING");
        }
        info!("{}", "FINISHED");
    }
    defer! {
        the_end();
    }
    if main_inner().is_err() {
        return ExitCode::from(1);
    }
    ExitCode::from(0)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct RegFile {
    flen: u64,
    pb: PathBuf,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct HashedFile {
    hash: [u8; 32],
    pb: PathBuf,
}

fn calc_hash(hasher: &mut sha2::Sha256, pat: &Path) -> Result<[u8; 32], CustomErr> {
    use sha2::Digest;
    use std::fs::*;
    //use sha2::{Sha256, Digest};
    //let mut hasher = Sha256::new();
    let mut file = File::open(pat)?;
    let _bytes_written = io::copy(&mut file, hasher)?;
    //let hash_bytes = hasher.finalize();
    let hash_bytes = hasher.finalize_reset();
    //let hash_bytes = hasher.finalize_boxed_reset();
    //use base64::{engine::general_purpose, Engine as _};
    //return Ok(general_purpose::STANDARD_NO_PAD.encode(hash_bytes));
    let retval: [u8; 32] = hash_bytes.as_slice().try_into()?;
    Ok(retval)
}

fn mk_hashedfile(hasher: &mut sha2::Sha256, pb: PathBuf) -> CustRes<HashedFile> {
    debug!("{}", "calc_hash begin");
    let hash = calc_hash(hasher, &pb)?;
    debug!("{}", "calc_hash end");
    Ok(HashedFile { hash, pb })
}

fn main_inner() -> CustRes<()> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    let mut stdin_w = StdinWrapper::default();
    let autodel = match env::var("DELETE_DUPLICATE_CLI_AUTO_DELETE") {
        Err(_) => false,
        Ok(inner) => inner.parse::<bool>()?,
    };
    let ign_size_gt = match env::var("DELETE_DUPLICATE_CLI_IGNORE_SIZE_GT") {
        Err(_) => u64::MAX,
        Ok(inner) => inner.parse::<u64>()?,
    };
    let ign_size_lt = match env::var("DELETE_DUPLICATE_CLI_IGNORE_SIZE_LT") {
        Err(_) => 0,
        Ok(inner) => inner.parse::<u64>()?,
    };
    let mut filelist = Vec::<RegFile>::new();
    let cwd = env::current_dir()?;
    coutln!("Start walking.");
    for dirent in WalkDir::new(cwd).follow_links(false) {
        let dirent = dirent?;
        let ft = dirent.file_type();
        if !ft.is_file() {
            continue;
        }
        let md = dirent.metadata()?;
        let flen = md.len();
        if flen < ign_size_lt || ign_size_gt < flen {
            continue;
        }
        filelist.push(RegFile {
            flen,
            pb: dirent.into_path(),
        })
    }
    coutln!("Finished walking, start sorting by size.");
    filelist.sort_unstable();
    coutln!(
        "Sorting finished, start checking hash. Total num: ",
        filelist.len()
    );
    let mut filelist = filelist.into_iter().peekable();
    let mut hashedlist = Vec::<HashedFile>::new();
    loop {
        let RegFile { flen, mut pb } = match filelist.next() {
            None => break,
            Some(inner) => inner,
        };
        loop {
            let refnext = match filelist.peek() {
                None => break,
                Some(inner) => inner,
            };
            if refnext.flen != flen {
                break;
            }
            if pb != PathBuf::default() {
                hashedlist.push(mk_hashedfile(&mut hasher, mem::take(&mut pb))?);
            }
            hashedlist.push(mk_hashedfile(&mut hasher, filelist.next().unwrap().pb)?);
        }
    }
    coutln!("Start sorting by hash.");
    hashedlist.sort_unstable();
    coutln!("Sorting finished. Total num: ", hashedlist.len());
    let mut filelist = hashedlist.into_iter().peekable();
    let mut groups: Vec<Vec<PathBuf>> = vec![];
    loop {
        let mut group = Vec::<PathBuf>::new();
        let HashedFile { hash, mut pb } = match filelist.next() {
            None => break,
            Some(inner) => inner,
        };
        loop {
            let refnext = match filelist.peek() {
                None => break,
                Some(inner) => inner,
            };
            if refnext.hash != hash {
                break;
            }
            if pb != PathBuf::default() {
                group.push(mem::take(&mut pb));
            }
            group.push(filelist.next().unwrap().pb);
        }
        if group.is_empty() {
            continue;
        }
        groups.push(group);
    }
    coutln!("Total number of groups: ", groups.len());
    'lst: for mut group in groups {
        if autodel {
            del_all_except_shortest_path(group)?;
            continue;
        }
        println!();
        for (idx, pb) in group.iter().enumerate() {
            coutln!(idx + 1, " ", pb.display());
        }
        let mut files_left = group.len();
        loop {
            cout_n_flush!(
                "INPUT NUMBER FOR DELETION (0 MEANS YOU ARE DONE WITH THIS GROUP & EMPTY MEANS DELETING ALL EXCEPT THE SHORTEST PATH):"
            );
            let linstr = match stdin_w.lines.next() {
                None => {
                    coutln!("Input ended.");
                    break 'lst;
                }
                Some(Err(err)) => {
                    return Err(err.into());
                }
                Some(Ok(linestr)) => linestr,
            };
            if linstr.is_empty() {
                del_all_except_shortest_path(group)?;
                break;
            }
            let mut idx = match linstr.parse::<usize>() {
                Err(_) => {
                    coutln!("Invalid index.");
                    continue;
                }
                Ok(inner) => inner,
            };
            if idx == 0 {
                //idx = usize::MAX; //docs is saying DO NOT rely on wrapping behavior, so here is manual wrap
                break;
            }
            idx -= 1;
            let deletion = match group.get_mut(idx) {
                None => {
                    coutln!("Wrong index.");
                    continue;
                }
                Some(inner) => inner,
            };
            if deletion == &PathBuf::default() {
                coutln!("Already deleted");
                continue;
            }
            coutln!("!!! DELETING !!!", deletion.display());
            fs::remove_file(mem::take(deletion))?;
            files_left -= 1;
            assert_always!(0 != files_left);
            if files_left == 1 {
                break;
            }
            coutln!("INPUT ANOTHER NUMBER IF YOU WANT TO DELETE MORE.");
        }
    }
    Ok(())
}

fn del_all_except_shortest_path(mut group: Vec<PathBuf>) -> CustRes<()> {
    group.sort_by_key(|k| k.as_os_str().len());
    for (idx, pb) in group.into_iter().enumerate() {
        if 0 == idx {
            continue;
        }
        coutln!("!!! DELETING !!!", pb.display());
        fs::remove_file(pb)?;
    }
    Ok(())
}
