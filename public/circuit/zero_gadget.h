#pragma once

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>

namespace circuit {

class zero_gadget1 : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x \in
   * y = x == 0 ? 0 : 1 
   */
  zero_gadget1(libsnark::protoboard<Fr>& pb,
               libsnark::linear_combination<Fr> const& x,
               const std::string& annotation_prefix = "")
      : x(x), libsnark::gadget<Fr>(pb, annotation_prefix) {
    t.allocate(pb);
    y.allocate(pb);

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(t, x, y)
    );
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(-y+1, x, 0)
    );
  }

  void generate_r1cs_witness() {
    Fr vx = x.evaluate(pb.full_variable_assignment());
    if(vx == 0){
      pb.val(t) = 0;
      pb.val(y) = 0;
    }else{
      pb.val(t) = 1 / vx;
      pb.val(y) = 1;
    }
  }

  libsnark::linear_combination<Fr> ret() const { return -y + 1; }

private:
  libsnark::pb_variable<Fr> t;

public:
  libsnark::linear_combination<Fr> const x;
  libsnark::pb_variable<Fr> y;
};

class zero_gadget2 : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x \in
   * y = x == 0 ? 0 : 1 
   */
  zero_gadget2(libsnark::protoboard<Fr>& pb,
               libsnark::linear_combination_array<Fr> const& x,
               const std::string& annotation_prefix = "")
      : x(x), libsnark::gadget<Fr>(pb, annotation_prefix) {
    t.allocate(pb, x.size());
    y.allocate(pb, x.size());
    
    for(size_t i=0; i<x.size(); i++){
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(t[i], x[i], y[i])
      );
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(-y[i]+1, x[i], 0)
      );
    }
  }

  void generate_r1cs_witness() {
    std::vector<Fr> vx(x.size());
    x.evaluate(pb.full_variable_assignment(), vx);
    for(size_t i=0; i<x.size(); i++){
      if(vx[i] == 0){
        pb.val(t[i]) = 0;
        pb.val(y[i]) = 0;
      }else{
        pb.val(t[i]) = 1 / vx[i];
        pb.val(y[i]) = 1;
      }
    }
  }

  libsnark::linear_combination<Fr> ret(size_t i) const { return -y[i]+1; }

private:
  libsnark::pb_variable_array<Fr> t;

public:
  libsnark::linear_combination_array<Fr> const x;
  libsnark::pb_variable_array<Fr> y;
};

class zero_gadget {
public:
  /**
   * 要求:x \in
   * y = x == 0 ? 0 : 1 
   */
  zero_gadget(libsnark::protoboard<Fr>& pb,
              libsnark::linear_combination<Fr> const& x,
              const std::string& annotation_prefix = ""){
    zero1.reset(new zero_gadget1(pb, x));
  }


  zero_gadget(libsnark::protoboard<Fr>& pb,
              libsnark::linear_combination_array<Fr> const& x,
               const std::string& annotation_prefix = ""){
    zero2.reset(new zero_gadget2(pb, x));
  }

  void generate_r1cs_witness() {
    if(zero1) zero1->generate_r1cs_witness();
    else if(zero2) zero2->generate_r1cs_witness();
    else CHECK(false, "");
  }

  libsnark::linear_combination<Fr> ret() {
    if(zero1) return zero1->ret();
    else CHECK(false, "");
  }

  libsnark::linear_combination<Fr> ret(size_t i) {
    if(zero2) return zero2->ret(i);
    else CHECK(false, "");
  }

  std::shared_ptr<zero_gadget1> zero1;
  std::shared_ptr<zero_gadget2> zero2;
};

inline bool TestZero1Gadget() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x;
  x.allocate(pb);
  libsnark::pb_linear_combination_array<Fr> a;
  // libsnark::linear_combination<Fr> a;
  zero_gadget1 gadget(pb, x);
  for(size_t i=0; i<2; i++){
      pb.val(x) = i;
      gadget.generate_r1cs_witness();
      CHECK((i == 0 ? 0 : 1) == gadget.ret().evaluate(pb.full_variable_assignment()).getInt64(), "");
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}

inline bool TestZero2Gadget() {
  Tick tick(__FN__);
  size_t n = 4;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x;
  x.allocate(pb, n);
  zero_gadget2 gadget(pb, x);
  for(size_t i=0; i<n; i++){
      pb.val(x[i]) = i;
  }
  gadget.generate_r1cs_witness();
  for(size_t i=0; i<n; i++){
    CHECK((pb.val(x[i]) == 0 ? 0 : 1) == gadget.ret(i).evaluate(pb.full_variable_assignment()).getInt64(), "");
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");

  return true;
}
}  // namespace circuit::fixed_point