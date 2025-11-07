#pragma once

#include "pack_gadget.h"
#include "grand_product_gadget.h"

namespace circuit {

// 约束数量: 2n+1
class shift_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x <= length
   * z = x * 2^y = x * ( (2^0)^{b_0} + .. + (2^{n-1})^{b_{n-1}} )
   */
  shift_gadget(libsnark::protoboard<Fr>& pb,
               libsnark::linear_combination<Fr> const& x,
               libsnark::linear_combination<Fr> const& y,
               size_t n, const std::string& annotation_prefix = "")
      :x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    pack.reset(new pack_gadget(pb, y, n));
    
    Fr pow2 = 2;
    for(size_t i=0; i<n; i++){
      t.emplace_back(pack->ret(i) * (pow2 - 1) + 1);
      pow2 *= pow2;
    }
    grand_product.reset(new grand_product_gadget(pb, t));

    z.allocate(pb);
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(grand_product->ret(), x, z)
    );
  }

  void generate_r1cs_witness() {
    pack->generate_r1cs_witness();
    grand_product->generate_r1cs_witness();
    Fr vx = x.evaluate(pb.full_variable_assignment());
    Fr vy = y.evaluate(pb.full_variable_assignment());
    Fr::pow(pb.val(z), 2, vy);
    pb.val(z) *= vx;
  }

  libsnark::pb_variable<Fr> ret() { return z; }

private:
  std::shared_ptr<pack_gadget> pack;
  std::shared_ptr<grand_product_gadget> grand_product;
  libsnark::linear_combination_array<Fr> t;

public:
  libsnark::linear_combination<Fr> const x;
  libsnark::linear_combination<Fr> const y;
  libsnark::pb_variable<Fr> z;
};

inline bool TestShiftGadget() {
  Tick tick(__FN__);
 
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x;
  libsnark::pb_variable<Fr> y;
  size_t n = 4;
  x.allocate(pb);
  y.allocate(pb);
  shift_gadget gadget(pb, x, y, n);
  for(size_t i=0; i<(1<<n); i++){
    for(size_t j=0; j<(1<<n); j++){
      pb.val(x) = i;
      pb.val(y) = j;
      gadget.generate_r1cs_witness();
      CHECK(pb.val(gadget.ret()).getInt64() == i * (1 << j), "");
    }
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints() << "\n";
  std::cout << Tick::GetIndentString()
            << "num_variables: " << pb.num_variables() << "\n";

  CHECK(pb.is_satisfied(), "");
  return true;
}
}