#pragma once

#include "zero_gadget.h"

namespace circuit{

class or_gadget1 : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x1, x2 \in {0, 1}
   * y = x1 or x2
   */
  or_gadget1(libsnark::protoboard<Fr>& pb,
             libsnark::linear_combination<Fr> const& x1,
             libsnark::linear_combination<Fr> const& x2,
             const std::string& annotation_prefix = "")
      : x1(x1), x2(x2), libsnark::gadget<Fr>(pb, annotation_prefix) {
    libsnark::linear_combination<Fr> t = x1 + x2;
    zero.reset(new zero_gadget(pb, t));
  }

  void generate_r1cs_witness() {
    zero->generate_r1cs_witness();
  }

  libsnark::linear_combination<Fr> ret() const { return -zero->ret()+1; }

private:
  std::shared_ptr<zero_gadget> zero;

public:
  libsnark::linear_combination<Fr> const x1;
  libsnark::linear_combination<Fr> const x2;
};

class or_gadget2 : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x1, ..., xn \in {0, 1}
   * y = x1 or ... or xn
   */
  or_gadget2(libsnark::protoboard<Fr>& pb,
            libsnark::linear_combination_array<Fr> const& x,
            const std::string& annotation_prefix = "")
      : x(x), libsnark::gadget<Fr>(pb, annotation_prefix) {
    libsnark::linear_combination<Fr> t;
    for(size_t i=0; i<x.size(); i++){
      t = t + x[i];
    }
    zero.reset(new zero_gadget(pb, t));
  }

  void generate_r1cs_witness() {
    zero->generate_r1cs_witness();
  }

  libsnark::linear_combination<Fr> ret() const { return -zero->ret()+1; }

private:
  std::shared_ptr<zero_gadget> zero;

public:
  libsnark::linear_combination_array<Fr> const x;
};

class or_gadget {
public:
  or_gadget(libsnark::protoboard<Fr>& pb,
             libsnark::linear_combination<Fr> const& x1,
             libsnark::linear_combination<Fr> const& x2,
             const std::string& annotation_prefix = "") {
    or1.reset(new or_gadget1(pb, x1, x2));
  }
  /**
   * 要求:x1, ..., xn \in {0, 1}
   * y = x1 or ... or xn
   */
  or_gadget(libsnark::protoboard<Fr>& pb,
            libsnark::linear_combination_array<Fr> const& x,
            const std::string& annotation_prefix = "") {
    or2.reset(new or_gadget2(pb, x));
  }

  void generate_r1cs_witness() {
    if(or1) or1->generate_r1cs_witness();
    else if(or2) or2->generate_r1cs_witness();
    else CHECK(false, "");
  }

  libsnark::linear_combination<Fr> ret() const { 
    if(or1) return or1->ret();
    else if(or2) return or2->ret();
    else CHECK(false, "");
  }

public:
  std::shared_ptr<or_gadget1> or1;
  std::shared_ptr<or_gadget2> or2;
};

inline bool TestOrGadget() {
  Tick tick(__FN__);
  size_t n = 4;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x;
  x.allocate(pb, n);
  or_gadget gadget(pb, x);
  for(size_t i=0; i<n; i++){
      pb.val(x[i]) = 1;
  }
  gadget.generate_r1cs_witness();
  CHECK(1 == gadget.ret().evaluate(pb.full_variable_assignment()).getInt64(), "");
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}
} 