#pragma once

#include "./floatvar.h"
#include "./select_gadget.h"

namespace circuit::flt {

/**
 * ret = min(x, y), 其中x, y的二进制长度为length
 */
class min_gadget : public libsnark::gadget<Fr> {
public:
  min_gadget(libsnark::protoboard<Fr>& pb,
             libsnark::linear_combination<Fr> const& x,
             libsnark::linear_combination<Fr> const& y,
             size_t length, const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix) {
    assert(length > 0);
    this->x.assign(pb, x);
    this->y.assign(pb, y);

    libsnark::pb_variable<Fr> less, less_or_eq;
    less.allocate(pb, "less");
    less_or_eq.allocate(pb, "less_or_eq");
    cmp.reset(new libsnark::comparison_gadget<Fr>(pb, length, this->x, this->y, less, less_or_eq, "cmp"));
    cmp->generate_r1cs_constraints();
    
    slt.reset(new select_gadget(pb, less, this->x, this->y));
    ret_ = slt->ret();
  }

  void generate_r1cs_witness() {
    cmp->generate_r1cs_witness();;
    slt->generate_r1cs_witness();
  }

  libsnark::linear_combination<Fr> ret() const { return ret_; }

private:
  std::shared_ptr<libsnark::comparison_gadget<Fr>> cmp;
  std::shared_ptr<select_gadget> slt;
  libsnark::pb_linear_combination<Fr> x, y;
  libsnark::linear_combination<Fr> ret_;
};

inline bool TestMinGadget() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, y;
  x.allocate(pb);
  y.allocate(pb);

  size_t n = 4;
  for(size_t i=1; i<(1 << n); i++){
    for(size_t j=1; j<(1 << n); j++){
      pb.val(x) = i;
      pb.val(y) = j;
      libsnark::linear_combination<Fr> lc_x = x - 1, lc_y = y - 1;
      min_gadget gadget(pb, lc_x, lc_y, n, "MinGadget");
      gadget.generate_r1cs_witness();
      CHECK(std::min(i-1, j-1) == gadget.ret().evaluate(pb.full_variable_assignment()).getInt64(), "");
    }
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  assert(pb.is_satisfied());
  return true;
}
}  // namespace circuit::fixed_point