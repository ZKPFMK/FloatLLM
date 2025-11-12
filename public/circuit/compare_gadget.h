#pragma once

#include "pack_gadget.h"
#include "or_gadget.h"

namespace circuit {
/**
 * 要求:x, y \in {0, 1}^n
 * less = x < y
 * less_or_eq =  x <= y
 * 
 * 约束数量, n+5 
 */
class comparison_gadget : public libsnark::gadget<Fr> {
private:
  std::shared_ptr<pack_gadget> pack;
  std::shared_ptr<or_gadget> orgt;
public:
  libsnark::pb_variable<Fr> lt;

  comparison_gadget(libsnark::protoboard<Fr>& pb,
                    const size_t n,
                    const libsnark::linear_combination<Fr> &x,
                    const libsnark::linear_combination<Fr> &y,
                    const std::string &annotation_prefix="") 
    : gadget<Fr>(pb, annotation_prefix) {
    lt.allocate(pb);

    Fr twon;
    Fr::pow(twon, 2, n);
    libsnark::linear_combination<Fr> z = y - x + twon;
    pack.reset(new pack_gadget(pb, z, n+1));
    
    libsnark::pb_variable_array<Fr> bits = pack->ret();
    libsnark::pb_variable<Fr> high_bit = bits[bits.size()-1];
    bits.resize(bits.size()-1);

    orgt.reset(new or_gadget(pb, bits));
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(orgt->ret(), pack->ret(n), lt)
    );
  };

  void generate_r1cs_witness(){
    pack->generate_r1cs_witness();
    orgt->generate_r1cs_witness();
    pb.val(lt) = orgt->ret().evaluate(pb.full_variable_assignment()) * pb.val(pack->ret(pack->ret().size()-1));
  }

  libsnark::pb_variable<Fr> ret_lt() const {
    return lt; 
  }

  libsnark::pb_variable<Fr> ret_leq() const {
    return pack->ret(pack->ret().size()-1); 
  }
};


/**
 * 要求:x, a, b \in {0, 1}^n, a<=b
 * x < a        => (1, 1)
 * a <= x <= b  => (0, 1)
 * b < x        => (0, 0)
 * 
 * 约束数量, 2n+10
 */
class range_gadget : public libsnark::gadget<Fr> {
private:
  std::shared_ptr<comparison_gadget> cmp_xa;
  std::shared_ptr<comparison_gadget> cmp_xb;
public:
  range_gadget(libsnark::protoboard<Fr>& pb,
               size_t n,
               libsnark::linear_combination<Fr> const& x,
               libsnark::linear_combination<Fr> const& a,
               libsnark::linear_combination<Fr> const& b,
               const std::string &annotation_prefix="") 
    : gadget<Fr>(pb, annotation_prefix) {

    // a < b: 观察第一个元组的第一个元素和第二个元组的第二个元素
    // x < a => (1, 1), (1, 1)
    // x = a => (0, 1), (1, 1)
    // a \in (a, b) => (0, 0), (1, 1)
    // x = b => (0, 0), (0, 1)
    // x > b => (0, 0), (0, 0)

    // a = b:
    // x < a => (1, 1), (1, 1)
    // x = a = b => (0, 1), (0, 1)
    // x > b => (0, 0), (0, 0)
    cmp_xa.reset(new comparison_gadget(pb, n, x, a));
    cmp_xb.reset(new comparison_gadget(pb, n, x, b));
  };

  void generate_r1cs_witness(){
    cmp_xa->generate_r1cs_witness();
    cmp_xb->generate_r1cs_witness();
  }

  libsnark::pb_variable_array<Fr> ret() const {
    libsnark::pb_variable_array<Fr> y;
    y.emplace_back(cmp_xa->ret_lt());
    y.emplace_back(cmp_xb->ret_leq());
    return y; 
  }
};

inline bool TestRangeGadget() {
  Tick tick(__FN__);
  size_t n = 4;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, a, b;
  x.allocate(pb);
  a.allocate(pb);
  b.allocate(pb);
  range_gadget gadget(pb, n, x, a, b);
  pb.val(a) = 3;
  pb.val(b) = 8;
  for(size_t i=0; i<(1<<n); i++){
    pb.val(x) = i;
    gadget.generate_r1cs_witness();
    if(i >= 3 && i <= 8){
      CHECK(0 == pb.val(gadget.ret()[0]).getInt64() && 1 == pb.val(gadget.ret()[1]).getInt64(), "");
    }else if(i < 3){
      CHECK(1 == pb.val(gadget.ret()[0]).getInt64() && 1 == pb.val(gadget.ret()[1]).getInt64(), "");
    }else{
      CHECK(0 == pb.val(gadget.ret()[0]).getInt64() && 0 == pb.val(gadget.ret()[1]).getInt64(), "");
    }
    CHECK(pb.is_satisfied(), "");
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";

  return true;
}

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