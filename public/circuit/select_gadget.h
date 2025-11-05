#pragma once

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>


namespace circuit {
class select_gadget1 : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:flag \in {0, 1}
   * z = b x + (1 - b) y
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
   * z = b x + (1 - b) y
   * 当b = 1 => z = x
   * 当b = 0 => z = y
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