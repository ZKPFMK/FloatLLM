#pragma once

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>

#include "ecc/ecc.h"

namespace circuit {

class compare_abs_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x, y \in {0, 1}
   * z = x * y = x and y 
   */
  compare_abs_gadget(libsnark::protoboard<Fr>& pb,
                     libsnark::linear_combination<Fr> const& a_exp,
                     libsnark::linear_combination<Fr> const& b_exp,
                     libsnark::linear_combination<Fr> const& a_man,
                     libsnark::linear_combination<Fr> const& b_man,
                     const std::string& annotation_prefix = "")
      : a_exp(a_exp), b_exp(b_exp), a_man(a_man), b_man(b_man),
        libsnark::gadget<Fr>(pb, annotation_prefix) {
    

  }

  void generate_r1cs_witness() {

  }

  libsnark::pb_variable<Fr> ret() const { return z; }

public:
  libsnark::linear_combination<Fr> const a_exp;
  libsnark::linear_combination<Fr> const b_exp;
  libsnark::linear_combination<Fr> const a_man;
  libsnark::linear_combination<Fr> const b_man;
};

inline bool TestAndGadget() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, y;
  x.allocate(pb);
  y.allocate(pb);
  compare_abs_gadget gadget(pb, x, y, "OrGadget");
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