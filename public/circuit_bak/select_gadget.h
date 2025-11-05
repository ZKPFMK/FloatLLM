#pragma once

#include "./floatvar.h"

namespace circuit::flt {

class select_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:flag \in {0, 1}
   * z = b x + (1 - b) y
   * 当b = 1 => z = x
   * 当b = 0 => z = y
   */
  select_gadget(libsnark::protoboard<Fr>& pb,
               libsnark::pb_linear_combination<Fr> const& b,
               libsnark::pb_linear_combination<Fr> const& x,
               libsnark::pb_linear_combination<Fr> const& y,
               const std::string& annotation_prefix = "")
      : b(b), x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    z.allocate(pb);
    r1.allocate(pb);
    r2.allocate(pb);
  
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(b, x, r1)
    );
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(-b+1 , y, r2)
    );
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, libsnark::linear_combination<Fr>(r1) + r2, z)
    );
  }

  void generate_r1cs_witness() {
    b.evaluate(this->pb);
    x.evaluate(this->pb);
    y.evaluate(this->pb);
    
    if(this->pb.lc_val(b) == 0){
        this->pb.val(r1) = 0;
        this->pb.val(r2) = this->pb.lc_val(y);
        this->pb.val(z) = this->pb.lc_val(y);
    }else{
        this->pb.val(r1) = this->pb.lc_val(x);
        this->pb.val(r2) = 0;
        this->pb.val(z) = this->pb.lc_val(x);
    }
  }

  libsnark::pb_variable<Fr> ret() { return z; }
private:
  libsnark::pb_variable<Fr> r1, r2;

public:
  libsnark::pb_linear_combination<Fr> const b;
  libsnark::pb_linear_combination<Fr> const x;
  libsnark::pb_linear_combination<Fr> const y;
  libsnark::pb_variable<Fr> z;
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
      CHECK(pb.val(gadget.ret()) ==  (i == 0 ? 3 : 2), "");
  }

  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints() << "\n";
  std::cout << Tick::GetIndentString()
            << "num_variables: " << pb.num_variables() << "\n";

CHECK(pb.is_satisfied(), "");
  return true;
}
}  // namespace circuit::fixed_point