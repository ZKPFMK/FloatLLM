#pragma once

#include "./floatvar.h"

namespace circuit::flt {

/**
 * ret = x or v, 其中x, y \in {0, 1}
 */
class or_gadget : public libsnark::gadget<Fr> {
public:
  or_gadget(libsnark::protoboard<Fr>& pb,
             libsnark::pb_linear_combination<Fr> const& x,
             libsnark::pb_linear_combination<Fr> const& y,
             const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    libsnark::pb_variable<Fr> z;
    z.allocate(pb);

    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(x, y, z)
    );
    // ret_ = a 

    //continue
  }

  void generate_r1cs_witness() {
    // pb.val(z) = 
  }

  libsnark::linear_combination<Fr> ret() const { return ret_; }

private:
  libsnark::pb_linear_combination<Fr> const& x;
  libsnark::pb_linear_combination<Fr> const& y;
  libsnark::pb_linear_combination<Fr> ret_;
};

inline bool TestMaxGadget() {
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
      max_gadget gadget(pb, lc_x, lc_y, n, "MaxGadget");
      gadget.generate_r1cs_witness();
      CHECK(std::max(i-1, j-1) == gadget.ret().evaluate(pb.full_variable_assignment()).getInt64(), "");
    }
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  assert(pb.is_satisfied());
  return true;
}
}  // namespace circuit::fixed_point