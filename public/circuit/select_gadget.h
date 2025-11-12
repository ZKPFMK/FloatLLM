#pragma once

#include "circuit.h"

namespace circuit {
// 约束数量: 1
class select_gadget1 : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:flag \in {0, 1}
   * z = b (x - y) + y
   * 当b = 1 => z = x
   * 当b = 0 => z = y
   */
  select_gadget1(libsnark::protoboard<Fr>& pb,
                libsnark::linear_combination<Fr> const& b,
                libsnark::linear_combination<Fr> const& x,
                libsnark::linear_combination<Fr> const& y,
                const std::string& annotation_prefix = "")
      : b(b), x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    t.allocate(pb);
  
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(b, x - y, t)
    );
    z = y + t;
  }

  void generate_r1cs_witness() {
    Fr vb = b.evaluate(pb.full_variable_assignment());
    Fr vx = x.evaluate(pb.full_variable_assignment());
    Fr vy = y.evaluate(pb.full_variable_assignment());
    if(vb == 0){
        this->pb.val(t) = 0;
    }else{
        this->pb.val(t) = vx - vy;
    }
  }

  libsnark::linear_combination<Fr> ret() { return z; }
private:
  libsnark::pb_variable<Fr> t;

public:
  libsnark::linear_combination<Fr> const b;
  libsnark::linear_combination<Fr> const x;
  libsnark::linear_combination<Fr> const y;
  libsnark::linear_combination<Fr> z;
};

class select_gadget2 : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:flag \in {0, 1}
   * z = b x + (1 - b) y
   * 当b = 1 => z = x
   * 当b = 0 => z = y
   */
  select_gadget2(libsnark::protoboard<Fr>& pb,
                 libsnark::linear_combination<Fr> const& b,
                 libsnark::linear_combination_array<Fr> const& x,
                 libsnark::linear_combination_array<Fr> const& y,
                 const std::string& annotation_prefix = "")
      : b(b), x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    CHECK(x.size() == y.size(), "");
    t.allocate(pb, x.size());
    
    for(size_t i=0; i<x.size(); i++){
      this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(b, x[i]-y[i], t[i])
      );
      z.emplace_back(t[i] + y[i]);
    }
  }

  void generate_r1cs_witness() {
    std::vector<Fr> vx(x.size());
    std::vector<Fr> vy(y.size());
    Fr vb = b.evaluate(pb.full_variable_assignment());
    x.evaluate(pb.full_variable_assignment(), vx);
    y.evaluate(pb.full_variable_assignment(), vy);
    
    if(vb == 0){
      for(size_t i=0; i<x.size(); i++){
        this->pb.val(t[i]) = 0;
      }
    }else if(vb == 1){
      for(size_t i=0; i<x.size(); i++){
        this->pb.val(t[i]) = vx[i]-vy[i];
      }
    }
  }

  libsnark::linear_combination<Fr> ret(size_t i) { return z[i]; }
private:
  libsnark::pb_variable_array<Fr> t;

public:
  libsnark::linear_combination<Fr> const b;
  libsnark::linear_combination_array<Fr> const x;
  libsnark::linear_combination_array<Fr> const y;
  libsnark::linear_combination_array<Fr> z;
};

class select_gadget {
public:
  /**
   * 要求:flag \in {0, 1}
   * z = y + b(x - y)
   * 当b = 1 => z = x
   * 当b = 0 => z = y
   * 约束数量: 1
   */
  select_gadget(libsnark::protoboard<Fr>& pb,
               libsnark::linear_combination<Fr> const& b,
               libsnark::linear_combination<Fr> const& x,
               libsnark::linear_combination<Fr> const& y,
               const std::string& annotation_prefix = "") {
    select1.reset(new select_gadget1(pb, b, x, y));
  }

  select_gadget(libsnark::protoboard<Fr>& pb,
                 libsnark::linear_combination<Fr> const& b,
                 libsnark::linear_combination_array<Fr> const& x,
                 libsnark::linear_combination_array<Fr> const& y,
                 const std::string& annotation_prefix = "") {
    select2.reset(new select_gadget2(pb, b, x, y));
  }

  void generate_r1cs_witness() {
    if(select1) select1->generate_r1cs_witness();
    else if(select2) select2->generate_r1cs_witness();
    else CHECK(false, "");
  }

  libsnark::linear_combination<Fr> ret() {
    if(select1) return select1->ret();
    else CHECK(false, "");
  }

  libsnark::linear_combination<Fr> ret(size_t i) {
    if(select2) return select2->ret(i);
    else CHECK(false, "");
  }

  std::shared_ptr<select_gadget1> select1;
  std::shared_ptr<select_gadget2> select2;
};


class ternary_select_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求: b0, b1 \in {0, 1}, 需要保证 != (1, 0)
   * (0, 0)=>x
   * (0, 1)=>y
   * (1, 1)=>z
   * ret = x + b1(y - x) + b0(z - y)
   * 当b = 1 => z = x
   * 当b = 0 => z = y
   * 约束数量: 2
   */
  ternary_select_gadget(libsnark::protoboard<Fr>& pb,
                        libsnark::linear_combination<Fr> const& b0,
                        libsnark::linear_combination<Fr> const& b1,
                        libsnark::linear_combination<Fr> const& x,
                        libsnark::linear_combination<Fr> const& y,
                        libsnark::linear_combination<Fr> const& z,
                        const std::string& annotation_prefix = "")
    : b0(b0), b1(b1), x(x), y(y), z(z),
      libsnark::gadget<Fr>(pb, annotation_prefix) {
    t0.allocate(pb);
    t1.allocate(pb);
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(b1, y-x, t1)
    );
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(b0, z-y, t0)
    );
    t = x + t0 + t1;
  }

  void generate_r1cs_witness() {
    Fr vb1 = b1.evaluate(pb.full_variable_assignment());
    Fr vb0 = b0.evaluate(pb.full_variable_assignment());
    Fr vx = x.evaluate(pb.full_variable_assignment());
    Fr vy = y.evaluate(pb.full_variable_assignment());
    Fr vz = z.evaluate(pb.full_variable_assignment());
    pb.val(t1) = vb1 * (vy - vx);
    pb.val(t0) = vb0 * (vz - vy);
  }

  libsnark::linear_combination<Fr> ret() {
    return t;
  }
  libsnark::pb_variable<Fr> t0, t1;
  libsnark::linear_combination<Fr> b0, b1;
  libsnark::linear_combination<Fr> x, y, z, t;
};

inline bool TestTernaryGadget() {
  Tick tick(__FN__);
 
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> b0, b1, x, y, z;
  b0.allocate(pb);
  b1.allocate(pb);
  x.allocate(pb);
  y.allocate(pb);
  z.allocate(pb);
  /**
   * 这里需要改为pb_linea
   */
  ternary_select_gadget gadget(pb, b0, b1, x, y, z, "select");
  pb.val(x) = 0;
  pb.val(y) = 1;
  pb.val(z) = 2;
  for(size_t i=0; i<2; i++){
    for(size_t j=0; j<2; j++){
      if(i == 1 && j == 0) continue;
      pb.val(b0) = i;
      pb.val(b1) = j;
      gadget.generate_r1cs_witness();
      CHECK(gadget.ret().evaluate(pb.full_variable_assignment()).getInt64() ==  (i+j == 0 ? 0 : (i+j == 1 ? 1 : 2)), "");
    }
  }

  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints() << "\n";
  std::cout << Tick::GetIndentString()
            << "num_variables: " << pb.num_variables() << "\n";

  CHECK(pb.is_satisfied(), "");
  return true;
}


inline bool TestSelectGadget() {
  Tick tick(__FN__);
 
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> b, x, y;
  b.allocate(pb, "b");
  x.allocate(pb, "x");
  y.allocate(pb, "y");
  /**
   * 这里需要改为pb_linea
   */
  select_gadget gadget(pb, b, x, y, "select");
  for(size_t i=0; i<2; i++){
      pb.val(b) = i;
      pb.val(x) = 2;
      pb.val(y) = 3;
      gadget.generate_r1cs_witness();
      CHECK(gadget.ret().evaluate(pb.full_variable_assignment()).getInt64() ==  (i == 0 ? 3 : 2), "");
  }

  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints() << "\n";
  std::cout << Tick::GetIndentString()
            << "num_variables: " << pb.num_variables() << "\n";

  CHECK(pb.is_satisfied(), "");
  return true;
}
}  // namespace circuit::fixed_point