#pragma once

#include "circuit.h"

namespace circuit {
// 约束数量: 1
class product_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * z = x * y
   */
  product_gadget(libsnark::protoboard<Fr>& pb,
                       libsnark::linear_combination<Fr> const& x,
                       libsnark::linear_combination<Fr> const& y,
                       const std::string& annotation_prefix = "")
      : x(x),y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
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

  libsnark::pb_variable<Fr> ret() { return z; }

public:
  libsnark::linear_combination<Fr> const x;
  libsnark::linear_combination<Fr> const y;
  libsnark::pb_variable<Fr> z;
};

inline bool TestProductGadget() {
  Tick tick(__FN__);
 
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x;
  libsnark::pb_variable<Fr> y;

  x.allocate(pb);
  y.allocate(pb);
  pb.val(x) = 2;
  pb.val(y) = 4;
  product_gadget gadget(pb, x, y);
  gadget.generate_r1cs_witness();
  CHECK(8 == pb.val(gadget.ret()).getInt64(), "");
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints() << "\n";
  std::cout << Tick::GetIndentString()
            << "num_variables: " << pb.num_variables() << "\n";

  CHECK(pb.is_satisfied(), "");
  return true;
}
}