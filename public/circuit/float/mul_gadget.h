#pragma once

#include "floatvar.h"
#include "circuit/or_gadget.h"
#include "circuit/xnor_gadget.h"
//205->
namespace circuit::flt {
class mul_gadget : public libsnark::gadget<Fr> {
public:
  void generate_r1cs_witness() {
    // Tick tick(__FN__);
    pb.val(prod) = pb.val(a.mantissa) * pb.val(b.mantissa);
    Fr m = pb.val(prod);
    DCHECK(m == 0 || (m >= Pow2[M*2] && m < Pow2[M*2+2]), "");

    prod_bits->generate_r1cs_witness();
    exp_range->generate_r1cs_witness();
    exp_delta->generate_r1cs_witness();
    prod_lshift->generate_r1cs_witness();
    prod_lshift_bits->generate_r1cs_witness();
    is_round_even->generate_r1cs_witness();
    carry->generate_r1cs_witness();

    Fr::pow(pb.val(two_delta), 2, exp_delta->ret().evaluate(pb.full_variable_assignment()));
    pb.val(pack_shift) = pack_man.evaluate(pb.full_variable_assignment()) * pb.val(two_delta);

    is_man_overflow->generate_r1cs_witness();
    man->generate_r1cs_witness();
    is_man_zero->generate_r1cs_witness();
    is_exp_overflow->generate_r1cs_witness();
    sign->generate_r1cs_witness();
    is_ret_zero->generate_r1cs_witness();
    is_ret_abnorm->generate_r1cs_witness();
    Fr v0 = (1 - is_ret_zero->ret()).evaluate(pb.full_variable_assignment());
    pb.val(c.sign) = v0 * (1 - sign->ret()).evaluate(pb.full_variable_assignment());
    pb.val(c.exponent) = v0 * (exp - (Pow2[E-1]+M-1)).evaluate(pb.full_variable_assignment());
    pb.val(c.mantissa) = v0 * man->ret().evaluate(pb.full_variable_assignment());
    pb.val(c.abnormal) = is_ret_abnorm->ret().evaluate(pb.full_variable_assignment());

    // debug();
  }

  void debug(){
    // std::cout << "exp_overflow:" << pb.val(exp_overflow->ret_leq()) << "\n";
  }
  std::shared_ptr<or_gadget> is_ret_zero;
  std::shared_ptr<or_gadget> is_ret_abnorm;
  std::shared_ptr<xnor_gadget> sign;

  std::shared_ptr<lshift_gadget> prod_lshift;
  std::shared_ptr<pack_gadget> prod_lshift_bits;
  std::shared_ptr<ternary_select_gadget> exp_delta;
  std::shared_ptr<range_gadget> exp_range;
  std::shared_ptr<pack_gadget> prod_bits;
  std::shared_ptr<zero_gadget> is_round_even; //round
  std::shared_ptr<select_gadget> carry;       //carry

  std::shared_ptr<zero_gadget> is_man_overflow;    //进位后是否越界
  std::shared_ptr<zero_gadget> is_man_zero;    //进位后尾数是否为0
  std::shared_ptr<select_gadget> man; //处理overflow后的尾数
  std::shared_ptr<comparison_gadget> is_exp_overflow;

  float_var c;
  libsnark::pb_variable<Fr> prod;
  libsnark::pb_variable<Fr> pack_shift;        //有效位的移位
  libsnark::pb_variable<Fr> two_delta;         //2^delta
  libsnark::linear_combination<Fr> pack_man;
  libsnark::linear_combination<Fr> exp;
  
 
  mul_gadget(libsnark::protoboard<Fr>& pb,
             float_var const& a,
             float_var const& b,
             const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        a(a), b(b) {
    Tick tick(__FN__);

    c.allocate(pb);
    prod.allocate(pb);
    two_delta.allocate(pb);
    pack_shift.allocate(pb);

    // m = m1 * m2
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(a.mantissa, b.mantissa, prod)
    );

    // prod的分解
    prod_bits.reset(new pack_gadget(pb, prod, M*2+2));

    // e1 + e2 + high_bit
    libsnark::linear_combination<Fr> sum = a.exponent+b.exponent+prod_bits->ret(2*M+1);

    // 判断exp是否属于区间[0, M+1]
    libsnark::linear_combination<Fr> lbound = Pow2[E-1]+M-1, rbound = Pow2[E-1]+M+M;
    exp_range.reset(new range_gadget(pb, E+2, sum, lbound, rbound));
    libsnark::pb_variable_array<Fr> range_flag = exp_range->ret();

    // (1, 1) => x < a        => M+2
    // (0, 1) => x \in [a, b] => M+1-x = M+1-(exp-lbound)
    // (0, 0) => x > b        => 0
    // 根据exp的取值范围来确定round时尾数应该移动的位数
    exp_delta.reset(new ternary_select_gadget(pb, range_flag[0], range_flag[1], 0, M+1-sum+lbound, M+2));

    // 将prod右移动l位, 其中l \in [0, k], 相当于将prod左移动k-l位; 这里的移位把之前norm的移位加上了
    prod_lshift.reset(new lshift_gadget(pb, prod, M+3-exp_delta->ret()-prod_bits->ret(M*2+1), misc::Log2UB(M+3)));

    // 将prod进行bit分解以便进行round
    prod_lshift_bits.reset(new pack_gadget(pb, prod_lshift->ret(), 3*M+4));

    // round || sticky
    libsnark::linear_combination<Fr> roud_stick=-Pow2[M*2+2];
    for(size_t i=0; i<2*M+3; i++){
      roud_stick = roud_stick + prod_lshift_bits->ret(i) * Pow2[i];
    }
    is_round_even.reset(new zero_gadget(pb, roud_stick));

    // 是否有进位
    carry.reset(new select_gadget(pb, is_round_even->ret(), prod_lshift_bits->ret(2*M+3), prod_lshift_bits->ret(2*M+2)));
    
    // 前M+1有效位
    libsnark::linear_combination<Fr> pack_man = carry->ret();
    for(size_t i=0; i<M+1; i++){
      pack_man = pack_man + prod_lshift_bits->ret(2*M+3+i) * Pow2[i];
    }

    // 计算2^{exp_delta}
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(two_delta, prod_lshift->pow2->ret(), (-prod_bits->ret(M*2+1)+2)*Pow2[M+2])
    );

    // 将有效位移位使得高位为1
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(pack_man, two_delta, pack_shift)
    );

    // 是否越界
    is_man_overflow.reset(new zero_gadget(pb, pack_shift - Pow2[M+1]));

    // 处理overflow后的尾数
    man.reset(new select_gadget(pb, is_man_overflow->ret(), Pow2[M], pack_shift));

    // 进位后尾数是否为0
    is_man_zero.reset(new zero_gadget(pb, man->ret()));

    // 尾数
    exp = sum+carry->ret();

    // 尾数是否上溢
    is_exp_overflow.reset(new comparison_gadget(pb, E+2, (1<<E)-1+M+lbound, exp));

    // 符号位
    sign.reset(new xnor_gadget(pb, a.sign, b.sign));

    // 处理值为0的情况: 输入有abnorml, 尾数为0, 指数上溢
    libsnark::linear_combination_array<Fr> ret_zero_case(4);
    ret_zero_case[0] = a.abnormal;
    ret_zero_case[1] = b.abnormal;
    ret_zero_case[2] = is_man_zero->ret();
    ret_zero_case[3] = is_exp_overflow->ret_leq();
    is_ret_zero.reset(new or_gadget(pb, ret_zero_case));

    // 处理值为abnorm的情况: 输入有abnormal, 指数上溢
    libsnark::linear_combination_array<Fr> ret_abnorm_case(3);
    ret_abnorm_case[0] = a.abnormal;
    ret_abnorm_case[1] = b.abnormal;
    ret_abnorm_case[2] = is_exp_overflow->ret_leq();
    is_ret_abnorm.reset(new or_gadget(pb, ret_abnorm_case));

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1-is_ret_zero->ret(), 1-sign->ret(), c.sign)
    );

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1-is_ret_zero->ret(), exp-lbound, c.exponent)
    );

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1-is_ret_zero->ret(), man->ret(), c.mantissa)
    );

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1, is_ret_abnorm->ret(), c.abnormal)
    );
  }

  float_var ret() const { return c; }

  float_var const& a;
  float_var const& b;
};

inline bool TestMul() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  float_var a, b;
  a.allocate(pb);
  b.allocate(pb);
  mul_gadget gadget(pb, a, b);
  const std::string path = std::string("/home/dj/program/gitwork/zk-Location/data/f32/mul_bak");
  std::vector<std::vector<uint32_t>> data;
  Read2DFile(path, data);

  for(size_t i=0; i<data.size(); i++){
    std::array<uint, 4> f1 = float_var::NewF32(data[i][0]);
    std::array<uint, 4> f2 = float_var::NewF32(data[i][1]);
    std::array<uint, 4> f3 = float_var::NewF32(data[i][2]);
    a.assign(pb, f1); b.assign(pb, f2);
    std::cout << i << "\n";
    // std::cout << "*********************************************************************\n";
    // std::cout << "a:" << f1[0] << "\t" << f1[1] << "\t" << f1[2] << "\t" << f1[3] << "\n";
    // std::cout << "b:" << f2[0] << "\t" << f2[1] << "\t" << f2[2] << "\t" << f2[3] << "\n";
    // std::cout << "c:" << f3[0] << "\t" << f3[1] << "\t" << f3[2] << "\t" << f3[3] << "\n";
    gadget.generate_r1cs_witness();
    CHECK(pb.is_satisfied(), "");
    CHECK(pb.val(gadget.ret().sign) == f3[0] && pb.val(gadget.ret().exponent) == f3[1] 
          && pb.val(gadget.ret().mantissa) == f3[2] && pb.val(gadget.ret().abnormal) == f3[3], "");
  }

  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
  return false;
}
};  // namespace circuit::vgg16