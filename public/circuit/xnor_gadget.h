#pragma once

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>

namespace circuit {

/**
 * ret = x xnor v, 其中x, y \in {0, 1}
 */
class xnor_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x, y \in {0, 1}
   * ret = 1 - (x + y - 2xy) = x xnor y 
   */
  xnor_gadget(libsnark::protoboard<Fr>& pb,
              libsnark::linear_combination<Fr> const& x,
              libsnark::linear_combination<Fr> const& y,
            const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    t.allocate(pb);
  
    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(x, y, t)
    );

    z = -x-y+t+t+1;
  }

  void generate_r1cs_witness() {
    Fr vx = x.evaluate(pb.full_variable_assignment());
    Fr vy = y.evaluate(pb.full_variable_assignment());
    pb.val(t) = vx * vy;
  }

  libsnark::linear_combination<Fr> ret() const { return z; }

private:
  libsnark::pb_variable<Fr> t;

public:
  libsnark::linear_combination<Fr> const x;
  libsnark::linear_combination<Fr> const y;
  libsnark::linear_combination<Fr> z;
};

inline bool TestXnorGadget() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, y;
  x.allocate(pb);
  y.allocate(pb);
  xnor_gadget gadget(pb, x, y, "OrGadget");
  for(size_t i=0; i<2; i++){
    for(size_t j=0; j<2; j++){
      pb.val(x) = i;
      pb.val(y) = j;
      gadget.generate_r1cs_witness();
      CHECK(!(i ^ j) == gadget.ret().evaluate(pb.full_variable_assignment()).getInt64(), "");
    }
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  assert(pb.is_satisfied());
  return true;
}
}  // namespace circuit::fixed_point