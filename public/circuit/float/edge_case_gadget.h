#pragma once

#include "floatvar.h"

#include "circuit/min_gadget.h"
#include "circuit/xnor_gadget.h"
#include "circuit/shift_gadget.h"


namespace circuit::flt {
class edge_case_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:e \in {0, 1}^E, m \in {0, 1}^{M+1}
   * 返回 (man1 << exp1) <= (man2 << exp2) ? 1 : 0
   */
  edge_case_gadget(libsnark::protoboard<Fr>& pb,
                   libsnark::linear_combination<Fr> const& sign1,
                   libsnark::linear_combination<Fr> const& sign2,
                   libsnark::linear_combination<Fr> const& exp1,
                   libsnark::linear_combination<Fr> const& exp2,
                   libsnark::linear_combination<Fr> const& man1,
                   libsnark::linear_combination<Fr> const& man2,
                   const std::string& annotation_prefix = "")
      : sign1(sign1), sign2(sign2), exp1(exp1), exp2(exp2), man1(man1), man2(man2),
        libsnark::gadget<Fr>(pb, annotation_prefix) {
      
      // norm所需的移位
      offset.allocate(pb);

      // 当diff超过M+3, 其实际上的效果等于M+3
      offset2.reset(new min_gadget(pb, exp1-exp2, M+3, E+1));

      // 对尾数进行移位, man1移动M+3, man2移动M+3-offset2
      libsnark::linear_combination<Fr> shift1 = man1 * Pow2[M+3];
      shift2.reset(new lshift_gadget(pb, man2, -offset2->ret()+M+3, misc::Log2UB(M+3)));

      // 符号位相同则+, 不同则-
      is_add_op.reset(new xnor_gadget(pb, sign1, sign2));

      // 根据符号位进行+或者-
      man.reset(new select_gadget(pb, is_add_op->ret(), shift1+shift2->ret(), shift1-shift2->ret()));

      // normalization, offset \in [0, M+2]
      shift.reset(new lshift_gadget(pb, man->ret(), offset, misc::Log2UB(M+2)));

      // shift的bits正确性
      shift_bits.reset(new pack_gadget(pb, shift->ret(), M*2+5));

      // shift是否为0
      is_shift_zero.reset(new zero_gadget(pb, shift->ret()));

      // shift的正确性: shift的高位为1或shift为0
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, is_shift_zero->ret()+shift_bits->ret(M*2+4), 1)
      );
  }

  void generate_r1cs_witness() {
    offset2->generate_r1cs_witness();
    shift2->generate_r1cs_witness();
    is_add_op->generate_r1cs_witness();
    man->generate_r1cs_witness();

    pb.val(offset) = 0;
    Fr x = man->ret().evaluate(pb.full_variable_assignment());
    if(x != 0) for(; x<Pow2[M*2+4]; x*=2, pb.val(offset)+=1);

    shift->generate_r1cs_witness();
    shift_bits->generate_r1cs_witness();
    is_shift_zero->generate_r1cs_witness();
  }

  libsnark::linear_combination<Fr> ret(size_t i) const { return shift_bits->ret(i); }

  libsnark::linear_combination_array<Fr> ret() const { return shift_bits->ret(); }

  libsnark::linear_combination<Fr> ret_offset() const { return offset; }

  libsnark::pb_variable<Fr> offset;

  std::shared_ptr<select_gadget> man;
  std::shared_ptr<lshift_gadget> shift;
  std::shared_ptr<min_gadget> offset2;
  std::shared_ptr<lshift_gadget> shift2;
  std::shared_ptr<xnor_gadget> is_add_op;
  std::shared_ptr<pack_gadget> shift_bits;
  std::shared_ptr<zero_gadget> is_shift_zero;
  
public:
  libsnark::linear_combination<Fr> const sign1;
  libsnark::linear_combination<Fr> const sign2;
  libsnark::linear_combination<Fr> const exp1;
  libsnark::linear_combination<Fr> const exp2;
  libsnark::linear_combination<Fr> const man1;
  libsnark::linear_combination<Fr> const man2;
};
}  // namespace circuit::fixed_point