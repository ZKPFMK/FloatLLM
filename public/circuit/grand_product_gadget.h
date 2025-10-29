#pragma once

#include "./floatvar.h"

namespace circuit::flt {

class grand_product_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x.size() > 1
   * ret = x[0] * x[1] * ... * x[n-1]
   */
  grand_product_gadget(libsnark::protoboard<Fr>& pb,
                       libsnark::pb_linear_combination_array<Fr> const& x,
                       const std::string& annotation_prefix = "")
      : x(x), libsnark::gadget<Fr>(pb, annotation_prefix) {
    assert(x.size() > 1);
    prod.allocate(this->pb, x.size()-1);
    this->pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(x[0], x[1], prod[0])
    );
    
    for(size_t i=2; i<x.size(); i++){
      this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(prod[i-2], x[i], prod[i-1])
      );
    }
  }

  void generate_r1cs_witness() {
    x.evaluate(this->pb);
    pb.val(prod[0]) = pb.lc_val(x[0]) * pb.lc_val(x[1]);
    for(size_t i=2; i<x.size(); i++){
        pb.val(prod[i-1]) = pb.val(prod[i-2]) * pb.lc_val(x[i]);
    }
  }

  libsnark::pb_variable<Fr> ret() { return prod[prod.size()-1]; }

private:
  libsnark::pb_linear_combination_array<Fr> const& x;
  libsnark::pb_variable_array<Fr> prod;
};

inline bool TestGrandProductGadget() {
  Tick tick(__FN__);
 
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x;
  libsnark::pb_linear_combination_array<Fr> y(3);

  x.allocate(pb, 3, "x");
  pb.val(x[0]) = 2;
  pb.val(x[1]) = 4;
  pb.val(x[2]) = 6;
  
  libsnark::linear_combination<Fr> z0 = x[1] - x[0];
  libsnark::linear_combination<Fr> z1 = x[2] - x[1];
  libsnark::linear_combination<Fr> z2 = 1;
  y[0].assign(pb, z0);
  y[1].assign(pb, z1);
  y[2].assign(pb, z2);

  grand_product_gadget gadget(pb, y, "grand product");


  gadget.generate_r1cs_witness();
  
  std::cout << Tick::GetIndentString() << pb.val(gadget.ret()) << "\n";
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints() << "\n";
  std::cout << Tick::GetIndentString()
            << "num_variables: " << pb.num_variables() << "\n";

  CHECK(pb.is_satisfied(), "");
  return true;
}
}