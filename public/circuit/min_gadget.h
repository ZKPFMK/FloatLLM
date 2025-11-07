#pragma once

#include "compare_gadget.h"
#include "select_gadget.h"

namespace circuit {

/**
 * ret = min(x, y), 其中x, y的二进制长度为n
 * 约束数量: n+6
 */
class min_gadget : public libsnark::gadget<Fr> {
public:
  min_gadget(libsnark::protoboard<Fr>& pb,
             libsnark::linear_combination<Fr> const& x,
             libsnark::linear_combination<Fr> const& y,
             size_t n, const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    assert(n > 0);

    cmp.reset(new comparison_gadget(pb, n, x, y));
    slt.reset(new select_gadget(pb, cmp->ret_lt(), x, y));
  }

  void generate_r1cs_witness() {
    cmp->generate_r1cs_witness();;
    slt->generate_r1cs_witness();
  }

  libsnark::linear_combination<Fr> ret() const { return slt->ret(); }

private:
  std::shared_ptr<comparison_gadget> cmp;
  std::shared_ptr<select_gadget> slt;

public:
  libsnark::linear_combination<Fr> const x;
  libsnark::linear_combination<Fr> const y;
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
      CHECK(std::min(i, j) == gadget.ret().evaluate(pb.full_variable_assignment()).getInt64(), "");
    }
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}
}  // namespace circuit::fixed_point