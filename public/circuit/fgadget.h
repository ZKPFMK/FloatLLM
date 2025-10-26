#pragma once

#include "floatvar.h"

namespace circuit::flt {
template <size_t E=11, size_t M=52>
class AddGadget : public libsnark::gadget<Fr> {
 public:
  AddGadget(libsnark::protoboard<Fr>& pb, 
          FloatVar & x, FloatVar & y,
          const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix){
  }

  void Assign(std::vector<Fr> const& state, std::vector<Fr> const& action) {
    assert(state.size() == in_state_.size() && action.size() == action_.size());

    for(int i=0; i<state.size(); i++){
        this->pb.val(in_state_[i]) = state[i];
    }
    for(int i=0; i<action.size(); i++){
        this->pb.val(action_[i]) = action[i];
    }
    generate_r1cs_witness();
  };

  static bool Test(std::vector<Fr> const& state, std::vector<Fr> const& action, std::vector<int> const& trap_state, Fr fin_state){
    libsnark::protoboard<Fr> pb;
    EnvGadget<D, N> gadget(pb, 64, 4, trap_state, "EnvGadget");
    std::cout << Tick::GetIndentString()
              << "num_constraints: " << pb.num_constraints()
              << ", num_variables: " << pb.num_variables() << "\n";

    gadget.Assign(state, action);

    return pb.is_satisfied() && pb.val(gadget.out_state_pack) == fin_state;
  };

 private:
  void generate_r1cs_constraints() {

  }

  void generate_r1cs_witness() {
    
  }

 private:

  FloatVar const& x ;
  FloatVar const& y;
};


inline bool EnvTest() {
  Tick tick(__FN__);
  return true;
}
};  // namespace circuit::frozenlake