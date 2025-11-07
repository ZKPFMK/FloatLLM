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


//208->193->190->185->177
namespace circuit::flt {
/**
 * 要求:s1, s2 \in {0, 1}; e1, e2 \in {0, 1}^E; m1, m2 \in {0, 1}^{M+1}
 * 返回 (man1 << exp1) <= (man2 << exp2) ? 1 : 0
 */
class add_gadget : public libsnark::gadget<Fr> {
public:

  void generate_r1cs_witness() {
    // Tick tick(__FN__);

    a_lt_b->generate_r1cs_witness();
    add_norm->generate_r1cs_witness();
    add_round->generate_r1cs_witness();

    exp_overflow->generate_r1cs_witness();
    exp_underflow->generate_r1cs_witness();
    is_ret_zero->generate_r1cs_witness();

    is_ret_abnorm->generate_r1cs_witness();
    // debug();
  }

  void debug(){
    std::cout << "x y:" << x_mantissa.evaluate(pb.full_variable_assignment()) << "\t" << y_mantissa.evaluate(pb.full_variable_assignment()) << "\n";
    std::cout << "ex ey:" << x_exponent.evaluate(pb.full_variable_assignment()) << "\t" << y_exponent.evaluate(pb.full_variable_assignment()) << "\n";


    std::cout << "zero cases:" << is_ret_zero->or2->x[0].evaluate(pb.full_variable_assignment()) << "\n"
                               << is_ret_zero->or2->x[1].evaluate(pb.full_variable_assignment()) << "\n"
                               << is_ret_zero->or2->x[2].evaluate(pb.full_variable_assignment()) << "\n"
                               << is_ret_zero->or2->x[3].evaluate(pb.full_variable_assignment()) << "\n"
                               << is_ret_zero->or2->x[4].evaluate(pb.full_variable_assignment()) << "\n";

    std::cout << "s e m:" << is_ret_zero->ret().evaluate(pb.full_variable_assignment()) * x_sign.evaluate(pb.full_variable_assignment()) << "\t"
                           << is_ret_zero->ret().evaluate(pb.full_variable_assignment()) * (x_exponent+1-add_norm->ret_offset()+add_round->ret_overflow()).evaluate(pb.full_variable_assignment()) << "\t"
                           << is_ret_zero->ret().evaluate(pb.full_variable_assignment()) * add_round->ret().evaluate(pb.full_variable_assignment()) << "\n";
  }

  std::shared_ptr<compare_abs_gadget> a_lt_b;
  std::shared_ptr<add_norm_gadget> add_norm;
  std::shared_ptr<add_round_gadget> add_round;
  std::shared_ptr<comparison_gadget> exp_overflow;
  std::shared_ptr<comparison_gadget> exp_underflow;
  std::shared_ptr<or_gadget> is_ret_zero;
  std::shared_ptr<or_gadget> is_ret_abnorm;
  std::shared_ptr<select_gadget> abnorm;
 
  add_gadget(libsnark::protoboard<Fr>& pb,
            float_var const& a,
            float_var const& b,
            float_var const& c,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        a(a), b(b), c(c) {
    Tick tick(__FN__);
    // 比较a和b的绝对值大小
    a_lt_b.reset(new compare_abs_gadget(pb, a.sign, b.sign, a.exponent, b.exponent, a.mantissa, b.mantissa));

    // 指数较大的数为x, 较小的为y
    x_sign = a_lt_b->ret_sign();
    x_exponent = a_lt_b->ret_exp();
    x_mantissa = a_lt_b->ret_man();;
    y_sign =  a.sign + b.sign - x_sign;
    y_exponent = a.exponent + b.exponent - x_exponent;
    y_mantissa = a.mantissa + b.mantissa - x_mantissa;

    // 尾数相加并normalization
    add_norm.reset(new add_norm_gadget(pb, x_sign, y_sign, x_exponent, y_exponent, x_mantissa, y_mantissa)) ;

    // 尾数round
    add_round.reset(new add_round_gadget(pb, add_norm->ret()));

    // 结果为0的情况: 输入有abnormal, 结果尾数为0, 指数上/下溢

    // 指数 = x_exp + 1 - norm_offset + man_overflow
    // 指数上溢: x_exp + 1 - norm_offset + man_overflow >= (1<<E)-1+M
    // 指数下溢: x_exp + 1 - norm_offset + man_overflow <= 0
    exp_overflow.reset(new comparison_gadget(pb, E+1, add_norm->ret_offset()+(1<<E)-1+M, x_exponent+1+add_round->ret_overflow()));
    exp_underflow.reset(new comparison_gadget(pb, E+1, x_exponent+1+add_round->ret_overflow(), add_norm->ret_offset()));

    libsnark::linear_combination_array<Fr> ret_zero_case(5);
    ret_zero_case[0] = a.abnormal;
    ret_zero_case[1] = b.abnormal;
    ret_zero_case[2] = 1 - add_norm->ret()[add_norm->ret().size()-1];
    ret_zero_case[3] = exp_overflow->ret_leq();
    ret_zero_case[4] = exp_underflow->ret_leq();
    is_ret_zero.reset(new or_gadget(pb, ret_zero_case));

    libsnark::linear_combination_array<Fr> ret_abnorm_case(4);
    ret_abnorm_case[0] = a.abnormal;
    ret_abnorm_case[1] = b.abnormal;
    ret_abnorm_case[2] = exp_overflow->ret_leq();
    ret_abnorm_case[3] = exp_underflow->ret_leq();
    is_ret_abnorm.reset(new or_gadget(pb, ret_abnorm_case));

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1-is_ret_zero->ret(), x_sign, c.sign)
    );

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1-is_ret_zero->ret(), x_exponent+1-add_norm->ret_offset()+add_round->ret_overflow(), c.exponent)
    );

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1-is_ret_zero->ret(), add_round->ret(), c.mantissa)
    );

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1, is_ret_abnorm->ret(), c.abnormal)
    );

  }

  float_var ret() const { return c; }

  float_var const& a;
  float_var const& b;
  float_var const& c;

  libsnark::linear_combination<Fr> x_sign;
  libsnark::linear_combination<Fr> y_sign;
  libsnark::linear_combination<Fr> x_exponent;
  libsnark::linear_combination<Fr> y_exponent;
  libsnark::linear_combination<Fr> x_mantissa;
  libsnark::linear_combination<Fr> y_mantissa;

};

inline bool TestAdd() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  float_var a, b, c;
  a.allocate(pb);
  b.allocate(pb);
  c.allocate(pb);
  add_gadget gadget(pb, a, b, c);
  const std::string path = std::string("/home/dj/program/gitwork/zk-Location/data/f32/add_bak");
  std::vector<std::vector<uint32_t>> data;
  Read2DFile(path, data);

  for(size_t i=0; i<data.size(); i++){
    std::array<uint, 4> f1 = float_var::NewF32(data[i][0]);
    std::array<uint, 4> f2 = float_var::NewF32(data[i][1]);
    std::array<uint, 4> f3 = float_var::NewF32(data[i][2]);
    a.assign(pb, f1); b.assign(pb, f2); c.assign(pb, f3);
    std::cout << i << "\n";
    // std::cout << "*********************************************************************\n";
    // std::cout << "a:" << f1[0] << "\t" << f1[1] << "\t" << f1[2] << "\t" << f1[3] << "\n";
    // std::cout << "b:" << f2[0] << "\t" << f2[1] << "\t" << f2[2] << "\t" << f2[3] << "\n";
    // std::cout << "c:" << f3[0] << "\t" << f3[1] << "\t" << f3[2] << "\t" << f3[3] << "\n";
    // gadget.generate_r1cs_witness();
    // CHECK(pb.is_satisfied(), "");
  }

  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
  return false;
}
};  // namespace circuit::vgg16