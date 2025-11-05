#pragma once

#include "./floatvar.h"
#include "./grand_product_gadget.h"

namespace circuit::flt {

class shift_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x <= length
   * y = 2^x = (2^0)^{b_0} + .. + (2^{n-1})^{b_{n-1}}
   */
  shift_gadget(libsnark::protoboard<Fr>& pb,
               libsnark::pb_linear_combination<Fr> const& x,
               size_t n, const std::string& annotation_prefix = "")
      :x(x), libsnark::gadget<Fr>(pb, annotation_prefix) {
    b.allocate(pb, n);
    pack.reset(new libsnark::packing_gadget<Fr>(pb, b, x));
    pack->generate_r1cs_constraints(true);
    
    y.resize(n);
    Fr pow2 = 2;
    for(size_t i=0; i<n; i++){
        libsnark::linear_combination<Fr> lc(1);
        lc.add_term(b[i], pow2-1);
        y[i].assign(pb, lc);
        pow2 *= pow2;
    }
    grand_product.reset(new grand_product_gadget(this->pb, y));
  }

  void generate_r1cs_witness() {
    pack->generate_r1cs_witness_from_packed();
    grand_product->generate_r1cs_witness();
  }

  libsnark::pb_variable<Fr> ret() { return grand_product->ret(); }

private:
  std::shared_ptr<libsnark::packing_gadget<Fr>> pack;
  std::shared_ptr<grand_product_gadget> grand_product;
  libsnark::pb_linear_combination_array<Fr> y;
  libsnark::pb_variable_array<Fr> b;

public:
  libsnark::pb_linear_combination<Fr> const x;
};

inline bool TestShiftGadget() {
  Tick tick(__FN__);
 
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x;
  size_t n = 4;
  x.allocate(pb, "x");
  shift_gadget gadget(pb, x, n, "shift");
  for(size_t i=0; i<(1<<n); i++){
    pb.val(x) = i;
    gadget.generate_r1cs_witness();
    CHECK(pb.val(gadget.ret()) == 1 << i, std::to_string(i) );
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints() << "\n";
  std::cout << Tick::GetIndentString()
            << "num_variables: " << pb.num_variables() << "\n";

  CHECK(pb.is_satisfied(), "");
  return true;
}
}