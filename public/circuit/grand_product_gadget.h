#pragma once

#include "circuit.h"

namespace circuit {
// 约束数量: n-1
class grand_product_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x.size() > 1
   * y = x[0] * x[1] * ... * x[n-1]
   */
  grand_product_gadget(libsnark::protoboard<Fr>& pb,
                       libsnark::linear_combination_array<Fr> const& x,
                       const std::string& annotation_prefix = "")
      : x(x), libsnark::gadget<Fr>(pb, annotation_prefix) {
    CHECK(x.size() > 1, "");

    y.allocate(this->pb, x.size()-1);
    this->pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(x[0], x[1], y[0])
    );
    
    for(size_t i=2; i<x.size(); i++){
      this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(y[i-2], x[i], y[i-1])
      );
    }
  }

  void generate_r1cs_witness() {
    std::vector<Fr> vx(x.size());
    x.evaluate(pb.full_variable_assignment(), vx);
    pb.val(y[0]) = vx[0] * vx[1];
    for(size_t i=2; i<x.size(); i++){
        pb.val(y[i-1]) = pb.val(y[i-2]) * vx[i];
    }
  }

  libsnark::pb_variable<Fr> ret() { return y[y.size()-1]; }

private:
  libsnark::pb_variable_array<Fr> y;

public:
  libsnark::linear_combination_array<Fr> const x;
};

inline bool TestGrandProductGadget() {
  Tick tick(__FN__);
 
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x;
  libsnark::linear_combination_array<Fr> y(3);

  x.allocate(pb, 3, "x");
  pb.val(x[0]) = 2;
  pb.val(x[1]) = 4;
  pb.val(x[2]) = 6;
  
  y[0] = x[1] - x[0];
  y[1] = x[2] - x[1];
  y[2] = 1;
  grand_product_gadget gadget(pb, y);
  gadget.generate_r1cs_witness();
  CHECK(4 == pb.val(gadget.ret()).getInt64(), "");
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints() << "\n";
  std::cout << Tick::GetIndentString()
            << "num_variables: " << pb.num_variables() << "\n";

  CHECK(pb.is_satisfied(), "");
  return true;
}
}