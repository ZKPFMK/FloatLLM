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

#include "circuit/float/add_gadget.h"
#include "circuit/grand_product_gadget.h"
#include "circuit/shift_gadget.h"
#include "circuit/max_gadget.h"
#include "circuit/min_gadget.h"
#include "circuit/or_gadget.h"
#include "circuit/xnor_gadget.h"
#include "circuit/zero_gadget.h"
#include "circuit/and_gadget.h"
#include "circuit/pack_gadget.h"
#include "circuit/compare_gadget.h"
#include "circuit/product_gadget.h"
#include "circuit/float/compare_abs_gadget.h"
#include "circuit/onehot_gadget.h"
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
  InitAll("./");

  circuit::flt::Pow2[0] = 1;
  for(size_t i=1; i<circuit::flt::Pow2.size(); i++){
    circuit::flt::Pow2[i] = circuit::flt::Pow2[i-1] * 2;
  }

  // circuit::flt::TestFloatVar();
  // circuit::flt::TestSelectGadget();
  // circuit::flt::TestPack1Gadget();
  // circuit::flt::TestPack2Gadget();
  // circuit::flt::TestZero1Gadget();
  // circuit::flt::TestZero2Gadget();
  // circuit::flt::TestAdd();
  // circuit::flt::TestGrandProductGadget();
  // circuit::flt::TestShiftGadget();
  // circuit::flt::TestMaxGadget();
  // circuit::flt::TestMinGadget();
  // circuit::flt::TestOrGadget();
  // circuit::flt::TestCompareGadget();
  // circuit::flt::TestXnorGadget();
  // circuit::TestProductGadget();
    circuit::Test1HotGadget();
  // circuit::flt::TestAndGadget();
  // circuit::flt::TestCmpAbsGadget();
  // circuit::flt::TestAdd();
  // circuit::flt::Test

  return 1;
}
