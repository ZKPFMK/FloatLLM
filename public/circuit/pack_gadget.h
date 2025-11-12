#pragma once

#include "circuit.h"

namespace circuit {
// 约束数量:n+1, n:比特长度
class pack_gadget : public libsnark::gadget<Fr> {

public:
  libsnark::pb_variable_array<Fr> b;
  libsnark::linear_combination<Fr> const x;

  pack_gadget(libsnark::protoboard<Fr> &pb,
              libsnark::linear_combination<Fr> const& x,
              size_t n, const std::string &annotation_prefix="") :
      x(x), gadget<Fr>(pb, annotation_prefix) {
    b.allocate(pb, n);

    Fr twoi = Fr::one();
    std::vector<libsnark::linear_term<Fr>> terms;
    for (size_t i = 0; i < b.size(); ++i, twoi += twoi) {
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(
          b[i], -b[i] + 1, 0
        )
      );

      terms.emplace_back(b[i] * twoi);
    }

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1, terms, x)
    );
  }

  void generate_r1cs_witness(){
    Fr vx = x.evaluate(pb.full_variable_assignment());

    mpz_class v = vx.getMpz();
    for (size_t i=0; i<b.size(); ++i){
        pb.val(b[i]).setMpz(v & 1);
        v = v >> 1;
    }
  }

  libsnark::pb_variable_array<Fr> ret() { 
    return b;
  }

  libsnark::pb_variable<Fr> ret(size_t i) { 
    DCHECK(i < b.size(), "");
    return b[i];
  }
};

inline bool TestPackGadget() {
  Tick tick(__FN__);
  size_t n = 4;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x;
  x.allocate(pb);
  pack_gadget gadget(pb, x, n);
  for(size_t i=0; i<(1 << n); i++){
      pb.val(x) = i;
      gadget.generate_r1cs_witness();
      for(size_t j=0; j<n; j++){
        CHECK((i >> j & 1) == pb.val(gadget.ret(j)).getInt64(), "")
      }
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
  CHECK(pb.is_satisfied(), "");
  return true;
}
}