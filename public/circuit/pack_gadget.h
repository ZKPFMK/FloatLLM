#pragma once

#include "circuit.h"

namespace circuit {
// 约束数量:n+1, n:比特长度
class pack_gadget1 : public libsnark::gadget<Fr> {
private:
    /* no internal variables */
public:
  libsnark::pb_variable_array<Fr> bits;
  libsnark::linear_combination<Fr> const packed;

  pack_gadget1(libsnark::protoboard<Fr> &pb,
                  libsnark::linear_combination<Fr> const& packed,
                  size_t n, const std::string &annotation_prefix="") :
      gadget<Fr>(pb, annotation_prefix), packed(packed) {
    bits.allocate(pb, n);

    for (size_t i = 0; i < bits.size(); ++i) {
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(
          bits[i], -bits[i] + 1, 0
        )
      );
    }

    Fr twoi = Fr::one();
    std::vector<libsnark::linear_term<Fr>> all_terms;
    for (auto &bit : bits) {
      all_terms.emplace_back(bit * twoi);
      twoi += twoi;
    }

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1, all_terms, packed)
    );
  }

  void generate_r1cs_witness(){
    Fr vpacked = packed.evaluate(pb.full_variable_assignment());

    mpz_class v = vpacked.getMpz();
    for (size_t i=0; i<bits.size(); ++i){
        pb.val(bits[i]).setMpz(v & 1);
        v = v >> 1;
    }
  }

  libsnark::pb_variable<Fr> ret(size_t i) { 
    DCHECK(i < bits.size(), "");
    return bits[i];
  }
};


class pack_gadget2 : public libsnark::gadget<Fr> {
private:
    /* no internal variables */
public:
  libsnark::linear_combination_array<Fr> const bits;
  libsnark::linear_combination<Fr> packed;

  pack_gadget2(libsnark::protoboard<Fr> &pb,
                libsnark::linear_combination_array<Fr> const& bits,
                const std::string &annotation_prefix="") :
      bits(bits), gadget<Fr>(pb, annotation_prefix) {
    Fr twoi = Fr::one();
    for (size_t i=0; i<bits.size(); i++) {
      packed = packed + bits[i] * twoi;
      twoi += twoi;
    }
  }

  void generate_r1cs_witness(){
  }

  libsnark::linear_combination<Fr> ret() { 
    return packed;
  }
};

class pack_gadget {
private:
    /* no internal variables */
public:
  pack_gadget(libsnark::protoboard<Fr> &pb,
              libsnark::linear_combination<Fr> const& packed,
              size_t n, const std::string &annotation_prefix="") {
    pack1.reset(new pack_gadget1(pb, packed, n));
  }

  pack_gadget(libsnark::protoboard<Fr> &pb,
              libsnark::linear_combination_array<Fr> const& bits,
              const std::string &annotation_prefix="") {
    pack2.reset(new pack_gadget2(pb, bits));
  }

  void generate_r1cs_witness() {
    if(pack1) pack1->generate_r1cs_witness();
    else if(pack2) pack2->generate_r1cs_witness();
    else CHECK(false, "");
  }

  libsnark::pb_variable<Fr> ret(size_t i) {
    if(pack1) return pack1->ret(i);
    else CHECK(false, "");
  }

  libsnark::linear_combination<Fr> ret() {
    if(pack2) return pack2->ret();
    else CHECK(false, "");
  }

  std::shared_ptr<pack_gadget1> pack1;
  std::shared_ptr<pack_gadget2> pack2;
};

inline bool TestPack1Gadget() {
  Tick tick(__FN__);
  size_t n = 4;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x;
  x.allocate(pb);
  pack_gadget1 gadget(pb, x, n);
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

inline bool TestPack2Gadget() {
  Tick tick(__FN__);
  size_t n = 4;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x;
  x.allocate(pb, n);
  pack_gadget2 gadget(pb, x);
  for(size_t i=0; i<n; i++){
      pb.val(x[i]) = 1;
  }
  gadget.generate_r1cs_witness();
  CHECK((1 << n) - 1 == gadget.ret().evaluate(pb.full_variable_assignment()).getInt64(), "");
  std::cout << Tick::GetIndentString()
          << "num_constraints: " << pb.num_constraints()
          << ", num_variables: " << pb.num_variables() << "\n";
  CHECK(pb.is_satisfied(), "");
  return true;
}
}