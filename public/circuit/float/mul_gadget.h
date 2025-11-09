#pragma once

#include "floatvar.h"
#include "circuit/select_gadget.h"
#include "circuit/shift_gadget.h"
#include "circuit/max_gadget.h"
#include "circuit/min_gadget.h"
#include "circuit/or_gadget.h"
#include "circuit/xnor_gadget.h"
#include "circuit/zero_gadget.h"
#include "circuit/and_gadget.h"
#include "circuit/compare_gadget.h"
#include "compare_abs_gadget.h"
#include "add_norm_gadget.h"
#include "add_round_gadget.h"
#include "circuit/onehot_gadget.h"


//208->193->190->185->177
namespace circuit::flt {

class mul_gadget : public libsnark::gadget<Fr> {
public:

  void generate_r1cs_witness() {
    Tick tick(__FN__);

    Fr m = pb.val(a.mantissa) * pb.val(b.mantissa);
    pb.val(man) = m;
    DCHECK(m == 0 || (m >= Pow2[M*2] && m < Pow2[M*2+2]), "");
    if(m >= Pow2[M*2+1]){
      pb.val(offset) = 1;
    }else{
      pb.val(offset) = 2;
    }

    pb.val(shift) = m * pb.val(offset);

    shift_bits->generate_r1cs_witness();

    is_shift_zero->generate_r1cs_witness();

    bits_len->generate_r1cs_witness();
    
    onehot_len->generate_r1cs_witness();

    is_round_even->generate_r1cs_witness();

    for(size_t i=0; i<M+1; i++){
      pb.val(prod1[i]) = pb.val(onehot_len->ret(i)) * pb.val(shift_bits->ret(M*2+1-i));
      pb.val(prod2[i]) = pb.val(onehot_len->ret(i)) * pb.val(shift_bits->ret(M*2-i));
      pb.val(prod3[i]) = pb.val(shift_bits->ret(M*2+1-i)) * Pow2[M-i];
    }

    carry->generate_r1cs_witness();
    is_overflow->generate_r1cs_witness();
    man_ret->generate_r1cs_witness();

    debug();
  }

  void debug(){
    Fr e = (a.exponent + b.exponent).evaluate(pb.full_variable_assignment());
    Fr m = pb.val(man);
    Fr oft = pb.val(offset);
    Fr sht = pb.val(shift);
    Fr len = bits_len->ret().evaluate(pb.full_variable_assignment());
    Fr round_even = is_round_even->ret().evaluate(pb.full_variable_assignment());
    Fr cry = carry->ret().evaluate(pb.full_variable_assignment());

    libsnark::linear_combination_array<Fr> validity_bits(M+1);
    for(size_t i=0; i<M+1; i++){
      for(size_t j=i; j<M+1; j++){
        validity_bits[i] = validity_bits[i] + onehot_len->ret(j);
      }
    }

    libsnark::linear_combination<Fr> pack_man = carry->ret();
    for(size_t i=0; i<M+1; i++){
      pack_man = pack_man + prod3[i];
    }

    std::cout << "e m:" << e << "\t" << m << "\n";
    std::cout << "offset:" << oft << "\n";
    std::cout << "shift:" << sht << "\n";
    std::cout << "validity bits len:" << len << "\n";
    std::cout << "is round to even:" << round_even << "\n";
    std::cout << "carry:" << cry << "\n";

    std::cout << "one hot:";
    for(size_t i=0; i<onehot_len->bits.size(); i++){
      std::cout << pb.val(onehot_len->ret(i)) << "\t";
    }
    std::cout << "\n";

    std::cout << "validity bits:";
    for(size_t i=0; i<validity_bits.size(); i++){
      std::cout << validity_bits[i].evaluate(pb.full_variable_assignment()) << "\t";
    }
    std::cout << "\n";
    std::cout << "pack:" << pack_man.evaluate(pb.full_variable_assignment()) << "\n";
  }

  std::shared_ptr<pack_gadget> shift_bits;
  std::shared_ptr<select_gadget> select_exp;
  std::shared_ptr<zero_gadget> zero_exp;
  std::shared_ptr<zero_gadget> is_shift_zero;
  std::shared_ptr<min_gadget> bits_len;
  std::shared_ptr<onehot_gadget> onehot_len;
  std::shared_ptr<zero_gadget> is_round_even;
  std::shared_ptr<select_gadget> carry;
  std::shared_ptr<zero_gadget> is_overflow;
  std::shared_ptr<select_gadget> man_ret;
  std::shared_ptr<comparison_gadget> exp_overflow;
  std::shared_ptr<comparison_gadget> exp_underflow;
 
  mul_gadget(libsnark::protoboard<Fr>& pb,
            float_var const& a,
            float_var const& b,
            float_var const& c,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        a(a), b(b), c(c) {
    Tick tick(__FN__);

    man.allocate(pb);
    shift.allocate(pb);
    offset.allocate(pb);
    prod1.allocate(pb, M+1);
    prod2.allocate(pb, M+1);
    prod3.allocate(pb, M+1);

    // 尾数相乘法
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(a.mantissa, b.mantissa, man)
    );

    // offset的正确性
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(offset-1, offset-2, 0)
    );

    // norm
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(man, offset, shift)
    );

    // shift的bit分解
    shift_bits.reset(new pack_gadget(pb, shift, M*2+2));

    // shift是否为0
    is_shift_zero.reset(new zero_gadget(pb, shift));


    // shift的正确性: shift的高位为1或shift为0
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1, is_shift_zero->ret()+shift_bits->ret(M*2+1), 1)
    );

    /**
     * 指数结果
     * 当e1+e2=0时, m=0, offset=1, e=1
     * 当e1=0 || e2=0, m=0, offset=1, e>=1
     * 当e1!=0 || e2!=0, e>=2
     * 
     *  */ 
    libsnark::linear_combination<Fr> exp = a.exponent + b.exponent + 2 - offset;
    zero_exp.reset(new zero_gadget(pb, exp));
    select_exp.reset(new select_gadget(pb, zero_exp->ret(), 1, exp));


    // 有效位长度
    bits_len.reset(new min_gadget(pb, select_exp->ret(), M+1, E+2));

    // 将len转化为one hot
    onehot_len.reset(new onehot_gadget(pb, bits_len->ret(), M+1));

    // 有效位标志
    libsnark::linear_combination_array<Fr> validity_bits(M+1);
    for(size_t i=0; i<M+1; i++){
      for(size_t j=i; j<M+1; j++){
        validity_bits[i] = validity_bits[i] + onehot_len->ret(j);
      }
    }

    // stick bits
    libsnark::linear_combination<Fr> pack_stick = 0;
    for(size_t i=0; i<M*2+2; i++){
      if(i < M+1) pack_stick = pack_stick+shift_bits->ret(i) * Pow2[i];
      else pack_stick = pack_stick+(-validity_bits[M*2+1-i]+1) * Pow2[i];
    }
    for(size_t i=0; i<M+1; i++){
      pack_stick = pack_stick - onehot_len->ret(M-i) * Pow2[M+1+i];
    }

    // round || stick == 100000
    is_round_even.reset(new zero_gadget(pb, pack_stick));

    libsnark::linear_combination<Fr> least_bit;
    libsnark::linear_combination<Fr> round_bit;
    libsnark::linear_combination<Fr> pack_man;
    
    for(size_t i=0; i<M+1; i++){
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(onehot_len->ret(i), shift_bits->ret(M*2+1-i), prod1[i])
      );
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(onehot_len->ret(i), shift_bits->ret(M*2-i), prod2[i])
      );
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(validity_bits[i]*Pow2[M-i], shift_bits->ret(M*2+1-i), prod3[i])
      );
      least_bit = least_bit + prod1[i];
      round_bit = round_bit + prod2[i];
      pack_man = pack_man + prod3[i];
    }
  
    // 是否有进位
    carry.reset(new select_gadget(pb, is_round_even->ret(), least_bit, round_bit));
    
    // 将前M位打包
    pack_man = pack_man + carry->ret();

    // 是否越界
    is_overflow.reset(new zero_gadget(pb, pack_man - Pow2[M+1]));

    // round结果
    man_ret.reset(new select_gadget(pb, is_overflow->ret(), Pow2[M], pack_man));

    // 结果为0的情况: 输入有abnormal, 结果尾数为0, 指数上/下溢

    // 指数 = exp
    // 指数上溢: exp + 150  >= (1<<E)-1+M
    // 指数下溢: x_exp <= 0, 不可能发生
    // exp_overflow.reset(new comparison_gadget(pb, E+1, add_norm->ret_offset()+(1<<E)-1+M, x_exponent+1+add_round->ret_overflow()));
    // exp_underflow.reset(new comparison_gadget(pb, E+1, x_exponent+1+add_round->ret_overflow(), add_norm->ret_offset()));
  }

  float_var ret() const { return c; }

  float_var const& a;
  float_var const& b;
  float_var const& c;

  libsnark::pb_variable_array<Fr> prod1;
  libsnark::pb_variable_array<Fr> prod2;
  libsnark::pb_variable_array<Fr> prod3;

  libsnark::pb_variable<Fr> man;
  libsnark::pb_variable<Fr> offset;
  libsnark::pb_variable<Fr> shift;

};

inline bool TestMul() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  float_var a, b, c;
  a.allocate(pb);
  b.allocate(pb);
  c.allocate(pb);
  mul_gadget gadget(pb, a, b, c);
  const std::string path = std::string("/home/dj/work/gitwork/Float/data/f32/mul");
  std::vector<std::vector<uint32_t>> data;
  Read2DFile(path, data);

  for(size_t i=0; i<data.size(); i++){
    std::array<uint, 4> f1 = float_var::NewF32(data[i][0]);
    std::array<uint, 4> f2 = float_var::NewF32(data[i][1]);
    std::array<uint, 4> f3 = float_var::NewF32(data[i][2]);
    a.assign(pb, f1); b.assign(pb, f2); c.assign(pb, f3);
    std::cout << i << "\n";
    std::cout << "*********************************************************************\n";
    std::cout << "a:" << f1[0] << "\t" << f1[1] << "\t" << f1[2] << "\t" << f1[3] << "\n";
    std::cout << "b:" << f2[0] << "\t" << f2[1] << "\t" << f2[2] << "\t" << f2[3] << "\n";
    std::cout << "c:" << f3[0] << "\t" << f3[1] << "\t" << f3[2] << "\t" << f3[3] << "\n";
    gadget.generate_r1cs_witness();
    CHECK(pb.is_satisfied(), "");
  }

  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
  return false;
}
};  // namespace circuit::vgg16