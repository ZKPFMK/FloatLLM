#include <assert.h>
#include <cryptopp/blake2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/randpool.h>

#include <iostream>

#include "debug/flags.h"
#include "ecc/ecc.h"
#include "log/tick.h"
#include "misc/misc.h"
#include "public.h"

bool DEBUG_CHECK = false;
bool BIG_MODE = false;
bool DISABLE_TBB = false;

bool InitAll(std::string const& data_dir) {
  InitEcc();

  std::string const kFileName = BIG_MODE ? "pds_pub_big.bin" : "pds_pub.bin";
  auto ecc_pds_file = data_dir + "/" + kFileName;
  if (!pc::OpenOrCreatePdsPub(ecc_pds_file)) {
    std::cerr << "Open or create pds pub file " << ecc_pds_file << " failed\n";
    return false;
  }

  return true;
}

std::unique_ptr<tbb::task_scheduler_init> tbb_init;

int main(int argc, char** argv) {
  return 1;
}
