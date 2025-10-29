#pragma once

#include "./floatvar.h"

namespace circuit::flt {

class select_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:flag \in {0, 1}
   * ret = flag epr1 + (1 - flag) epr2
   * 当flag = 1 => ret = epr1
   * 当flag = 0 => ret = epr2
   */
  select_gadget(libsnark::protoboard<Fr>& pb,
               libsnark::linear_combination<Fr> const& flag,
               libsnark::linear_combination<Fr> const& epr1,
               libsnark::linear_combination<Fr> const& epr2,
               const std::string& annotation_prefix = "")
      :libsnark::gadget<Fr>(pb, annotation_prefix) {
    
    ret1.allocate(pb);
    ret2.allocate(pb);
    this->flag.assign(this->pb, flag);
    this->epr1.assign(this->pb, epr1);
    this->epr2.assign(this->pb, epr2);

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(flag, epr1, ret1)
    );
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(libsnark::linear_combination<Fr>(1) - flag, epr2, ret2)
    );
    ret_ = ret1 + ret2;
  }

  void generate_r1cs_witness() {
    flag.evaluate(this->pb);
    epr1.evaluate(this->pb);
    epr2.evaluate(this->pb);
    if((this->pb).lc_val(flag) == 0){
        this->pb.val(ret1) = 0;
        this->pb.val(ret2) = this->pb.lc_val(epr2);
    }else{
        this->pb.val(ret1) = this->pb.lc_val(epr1);
        this->pb.val(ret2) = 0;
    }
  }

  libsnark::linear_combination<Fr> ret() { return ret_; }

 private:
  libsnark::pb_linear_combination<Fr> epr1;
  libsnark::pb_linear_combination<Fr> epr2;
  libsnark::linear_combination<Fr> ret_;
  libsnark::pb_variable<Fr> ret1, ret2;
  libsnark::pb_linear_combination<Fr> flag;
};

inline bool TestSelectGadget() {
  Tick tick(__FN__);
 
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> b, x, y;
  b.allocate(pb, "b");
  x.allocate(pb, "x");
  y.allocate(pb, "y");
  select_gadget gadget(pb, libsnark::linear_combination<Fr>(1) - b, x - y, y - x, "select");
  pb.val(b) = 1;
  pb.val(x) = 2;
  pb.val(y) = 1;

  gadget.generate_r1cs_witness();
  
  std::cout << Tick::GetIndentString() << gadget.ret().evaluate(pb.full_variable_assignment()) << "\n";
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints() << "\n";
  std::cout << Tick::GetIndentString()
            << "num_variables: " << pb.num_variables() << "\n";

CHECK(pb.is_satisfied(), "");
  return true;
}
}  // namespace circuit::fixed_point