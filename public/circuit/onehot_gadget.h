#pragma once

#include "circuit.h"

namespace circuit {
// 约束数量:n+1, n:比特长度
class onehot_gadget : public libsnark::gadget<Fr> {
private:
    /* no internal variables */
public:
  libsnark::pb_variable_array<Fr> bits;
  libsnark::linear_combination<Fr> const x;

  onehot_gadget(libsnark::protoboard<Fr> &pb,
                libsnark::linear_combination<Fr> const& x,
                size_t n, const std::string &annotation_prefix="") :
      gadget<Fr>(pb, annotation_prefix), x(x) {
    bits.allocate(pb, n);

    for (size_t i = 0; i < bits.size(); ++i) {
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(
          bits[i], -bits[i] + 1, 0
        )
      );
    }

    std::vector<libsnark::linear_term<Fr>> terms1;
    std::vector<libsnark::linear_term<Fr>> terms2;
    for (size_t i = 0; i < bits.size(); ++i) {
      terms1.emplace_back(bits[i] * i);
      terms2.emplace_back(bits[i]);
    }

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1, terms1, x)
    );
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1, terms2, 1)
    );
  }

  void generate_r1cs_witness(){
    uint vx = x.evaluate(pb.full_variable_assignment()).getUint64();
    DCHECK(vx < bits.size(), ""); 
    for (size_t i=0; i<bits.size(); ++i){
        pb.val(bits[i]) = 0;
    }
    pb.val(bits[vx]) = 1;
  }

  libsnark::pb_variable<Fr> ret(size_t i) { 
    DCHECK(i < bits.size(), "");
    return bits[i];
  }
};


inline bool Test1HotGadget() {
  Tick tick(__FN__);
  size_t n = 4;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x;
  x.allocate(pb);
  onehot_gadget gadget(pb, x, n);
  for(size_t i=0; i<n; i++){
      pb.val(x) = i;
      gadget.generate_r1cs_witness();
      for(size_t j=0; j<n; j++){
        if(i == j){
          CHECK(1 == pb.val(gadget.ret(j)).getInt64(), "");
        } else {
          CHECK(0 == pb.val(gadget.ret(j)).getInt64(), "");
        }
      }
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
  CHECK(pb.is_satisfied(), "");
  return true;
}
}