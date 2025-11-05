#pragma once

#include "pack_gadget.h"
#include "or_gadget.h"

namespace circuit {
/**
 * 要求:x, y \in {0, 1}^n
 * less = x < y
 * less_or_eq =  x <= y
 */
class comparison_gadget : public libsnark::gadget<Fr> {
private:
  std::shared_ptr<pack_gadget> pack;
  std::shared_ptr<or_gadget> orgt;
public:
  const size_t n;
  const libsnark::linear_combination<Fr> x;
  const libsnark::linear_combination<Fr> y;
  libsnark::pb_variable<Fr> less;

  comparison_gadget(libsnark::protoboard<Fr>& pb,
                    const size_t n,
                    const libsnark::linear_combination<Fr> &x,
                    const libsnark::linear_combination<Fr> &y,
                    const std::string &annotation_prefix="") :
      n(n), x(x), y(y), gadget<Fr>(pb, annotation_prefix) {
    less.allocate(pb);

    Fr pow2n;
    Fr::pow(pow2n, 2, n);
    libsnark::linear_combination<Fr> z = y - x + pow2n;
    pack.reset(new pack_gadget(pb, z, n+1));
    
    libsnark::linear_combination_array<Fr> least_bits(n);
    for(size_t i=0; i<n; i++) {
      least_bits[i] = pack->ret(i);
    }
    orgt.reset(new or_gadget(pb, least_bits));
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(orgt->ret(), pack->ret(n), less)
    );
  };

  void generate_r1cs_witness(){
    pack->generate_r1cs_witness();
    orgt->generate_r1cs_witness();
    pb.val(less) = orgt->ret().evaluate(pb.full_variable_assignment()) * pb.val(pack->ret(n));
  }

  libsnark::pb_variable<Fr> ret_lt() const {
    return less; 
  }

  libsnark::pb_variable<Fr> ret_leq() const {
    return pack->ret(n); 
  }
};

inline bool TestCompareGadget() {
  Tick tick(__FN__);
  size_t n = 4;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, y;
  x.allocate(pb);
  y.allocate(pb);
  comparison_gadget gadget(pb, n, x, y);
  for(size_t i=0; i<n; i++){
    for(size_t j=0; j<n; j++){
      pb.val(x) = i;
      pb.val(y) = j;
      gadget.generate_r1cs_witness();
      CHECK(i < j ? 1 : 0 == pb.val(gadget.ret_lt()).getInt64(), "");
    }
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  assert(pb.is_satisfied());

  return true;
}
}