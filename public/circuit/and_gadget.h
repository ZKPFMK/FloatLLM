#pragma once

#include "circuit.h"

namespace circuit {

class and_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x, y \in {0, 1}
   * z = x * y = x and y 
   */
  and_gadget(libsnark::protoboard<Fr>& pb,
            libsnark::linear_combination<Fr> const& x,
            libsnark::linear_combination<Fr> const& y,
            const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    z.allocate(pb);

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(x, y, z)
    );
  }

  void generate_r1cs_witness() {
    Fr vx = x.evaluate(pb.full_variable_assignment());
    Fr vy = y.evaluate(pb.full_variable_assignment());
    pb.val(z) = vx * vy;
  }

  libsnark::pb_variable<Fr> ret() const { return z; }

public:
  libsnark::linear_combination<Fr> const x;
  libsnark::linear_combination<Fr> const y;
  libsnark::pb_variable<Fr> z;
};

inline bool TestAndGadget() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, y;
  x.allocate(pb);
  y.allocate(pb);
  and_gadget gadget(pb, x, y, "OrGadget");
  for(size_t i=0; i<2; i++){
    for(size_t j=0; j<2; j++){
      pb.val(x) = i;
      pb.val(y) = j;
      gadget.generate_r1cs_witness();
      CHECK((i & j) == pb.val(gadget.ret()).getInt64(), "");
    }
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}
}  // namespace circuit::fixed_point