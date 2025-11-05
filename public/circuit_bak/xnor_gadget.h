#pragma once

#include "./floatvar.h"

namespace circuit::flt {

/**
 * ret = x xnor v, 其中x, y \in {0, 1}
 */
class xnor_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x, y \in {0, 1}
   * ret = 1 - (x + y - 2xy) = x xnor y 
   */
  xnor_gadget(libsnark::protoboard<Fr>& pb,
            libsnark::pb_linear_combination<Fr> const& x,
            libsnark::pb_linear_combination<Fr> const& y,
            const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    z.allocate(pb);
    t.allocate(pb);
  
    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(x, y, t)
    );
    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(-x-y+t+t+1, 1, z)
    );
  }

  void generate_r1cs_witness() {
    x.evaluate(pb);
    y.evaluate(pb);
    pb.val(t) = pb.lc_val(x) * pb.lc_val(y);
    pb.val(z) = pb.lc_val(t) * 2 - pb.lc_val(x) - pb.lc_val(y) + 1;
  }

  libsnark::pb_variable<Fr> ret() const { return z; }

private:
  libsnark::pb_variable<Fr> t;

public:
  libsnark::pb_linear_combination<Fr> x;
  libsnark::pb_linear_combination<Fr> y;
  libsnark::pb_variable<Fr> z;
};

inline bool TestXnorGadget() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, y;
  x.allocate(pb);
  y.allocate(pb);
  xnor_gadget gadget(pb, x, y, "OrGadget");
  for(size_t i=0; i<2; i++){
    for(size_t j=0; j<2; j++){
      pb.val(x) = i;
      pb.val(y) = j;
      gadget.generate_r1cs_witness();
      CHECK(!(i ^ j) == pb.val(gadget.ret()).getInt64(), "");
    }
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  assert(pb.is_satisfied());
  return true;
}
}  // namespace circuit::fixed_point