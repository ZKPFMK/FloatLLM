#pragma once

#include "./floatvar.h"
#include "./select_gadget.h"

namespace circuit::flt {

/**
 * ret = min(x, y), 其中x, y的二进制长度为n
 */
class min_gadget : public libsnark::gadget<Fr> {
public:
  min_gadget(libsnark::protoboard<Fr>& pb,
             libsnark::pb_linear_combination<Fr> const& x,
             libsnark::pb_linear_combination<Fr> const& y,
             size_t n, const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    assert(n > 0);

    libsnark::pb_variable<Fr> less, less_or_eq;
    less.allocate(pb);
    less_or_eq.allocate(pb);
    cmp.reset(new libsnark::comparison_gadget<Fr>(pb, n, x, y, less, less_or_eq));
    cmp->generate_r1cs_constraints();
    
    slt.reset(new select_gadget(pb, less, x, y));
  }

  void generate_r1cs_witness() {
    cmp->generate_r1cs_witness();;
    slt->generate_r1cs_witness();
  }

  libsnark::pb_variable<Fr> ret() const { return slt->ret(); }

private:
  std::shared_ptr<libsnark::comparison_gadget<Fr>> cmp;
  std::shared_ptr<select_gadget> slt;

public:
  libsnark::pb_linear_combination<Fr> const x;
  libsnark::pb_linear_combination<Fr> const y;
};

inline bool TestMinGadget() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, y;
  x.allocate(pb);
  y.allocate(pb);
  size_t n = 4;
  min_gadget gadget(pb, x, y, n, "MinGadget");
  for(size_t i=1; i<(1 << n); i++){
    for(size_t j=1; j<(1 << n); j++){
      pb.val(x) = i;
      pb.val(y) = j;
      gadget.generate_r1cs_witness();
      CHECK(std::min(i, j) == pb.val(gadget.ret()).getInt64(), "");
    }
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  assert(pb.is_satisfied());
  return true;
}
}  // namespace circuit::fixed_point