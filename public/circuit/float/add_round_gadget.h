#pragma once

#include "floatvar.h"

#include "circuit/min_gadget.h"
#include "circuit/xnor_gadget.h"
#include "circuit/shift_gadget.h"


namespace circuit::flt {
class add_round_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:e \in {0, 1}^E, m \in {0, 1}^{M+1}
   * 返回 (man1 << exp1) <= (man2 << exp2) ? 1 : 0
   */
  add_round_gadget(libsnark::protoboard<Fr>& pb,
                  libsnark::linear_combination_array<Fr> const& bits,
                  const std::string& annotation_prefix = "")
      : bits(bits),
        libsnark::gadget<Fr>(pb, annotation_prefix) {
    
    // (roud || stick) == 1 << M+3
    libsnark::linear_combination<Fr> pack_roud_stick = -Pow2[M+3];
    for(size_t i=0; i<M+4; i++){
      pack_roud_stick = pack_roud_stick + bits[i] * Pow2[i];
    }
    is_round_even.reset(new zero_gadget(pb, pack_roud_stick));

    // 如果上述式子成立, 则进位取决于有效位的最后一位, 取决于round bit
    carry.reset(new select_gadget(pb, is_round_even->ret(), bits[M+4], bits[M+3]));
    
    // 将前M位打包
    libsnark::linear_combination<Fr> pack_man = carry->ret();
    for(size_t i=0; i<M+1; i++){
      pack_man = pack_man + bits[M+4+i] * Pow2[i];
    }

    // 是否越界
    is_overflow.reset(new zero_gadget(pb, pack_man - Pow2[M+1]));

    // round结果
    man.reset(new select_gadget(pb, is_overflow->ret(), Pow2[M], pack_man));
  }

  void generate_r1cs_witness() {
    is_round_even->generate_r1cs_witness();
    carry->generate_r1cs_witness();
    is_overflow->generate_r1cs_witness();
    man->generate_r1cs_witness();
  }

  libsnark::linear_combination<Fr> ret() const { return man->ret(); }

  libsnark::linear_combination<Fr> ret_overflow() const { return is_overflow->ret(); }

  libsnark::linear_combination<Fr> ret_carry() const { return carry->ret(); }

  std::shared_ptr<select_gadget> man;
  std::shared_ptr<select_gadget> carry;
  std::shared_ptr<zero_gadget> is_overflow;
  std::shared_ptr<zero_gadget> is_round_even;
  
public:
  libsnark::linear_combination_array<Fr> const bits;
};
}  // namespace circuit::fixed_point