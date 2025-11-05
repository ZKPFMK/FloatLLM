#pragma once

#include "floatvar.h"
#include "../select_gadget.h"
#include "../shift_gadget.h"
#include "../max_gadget.h"
#include "../min_gadget.h"
#include "../or_gadget.h"
#include "../xnor_gadget.h"
#include "../zero_gadget.h"
#include "../and_gadget.h"
#include "../compare_gadget.h"


//208->193->190
namespace circuit::flt {

class add_gadget : public libsnark::gadget<Fr> {
public:

  void generate_r1cs_witness() {
    generate_r1cs_witness1();
    generate_r1cs_witness2();
    generate_r1cs_witness3();
    generate_r1cs_witness4();
  }

  void generate_r1cs_witness1() {
    // Tick tick(__FN__);
    cmp_exp_ab->generate_r1cs_witness();
    cmp_man_ab->generate_r1cs_witness();
    eq_2_or_3->generate_r1cs_witness();
    a_lt_b->generate_r1cs_witness();
    slt_xy->generate_r1cs_witness();
    min_exp->generate_r1cs_witness();

    // debug_align();
  }

  void debug_align(){
    std::cout << "x y:" << x_mantissa.evaluate(pb.full_variable_assignment()) << "\t" << y_mantissa.evaluate(pb.full_variable_assignment()) << "\n";
    std::cout << "max e:" << x_exponent.evaluate(pb.full_variable_assignment()) << "\t" << y_exponent.evaluate(pb.full_variable_assignment()) << "\n";
  }

  std::shared_ptr<comparison_gadget> cmp_exp_ab;
  std::shared_ptr<comparison_gadget> cmp_man_ab;
  std::shared_ptr<grand_product_gadget> eq_2_or_3;
  std::shared_ptr<zero_gadget> a_lt_b;
  std::shared_ptr<select_gadget> slt_xy;
  std::shared_ptr<min_gadget> min_exp;

  void align_exp(){
    Tick tick(__FN__);
    // 比较指数大小
    cmp_exp_ab.reset(new comparison_gadget(pb, E+1, a.exponent, b.exponent));

    // 比较尾数大小
    cmp_man_ab.reset(new comparison_gadget(pb, M+1, a.mantissa, b.mantissa));

    // leq_exp, lt_exp: 
    //    0, 0 => ea > eb
    //    0, 1 => ea = eb
    //    1, 1 => ea < eb
    // leq_man, lt_man: 
    //    0, 0 => ma > mb
    //    0, 1 => ma = mb
    //    1, 1 => ma < mb
    /***
     * 上三角矩阵的和=2 or 上三角矩阵的和=2 => b > a
     * exp man exp man exp man | exp man exp man exp man | exp man exp man exp man                               
     *  0   0   0   0   0   1  |  0   0   0   0   0   1  |  1   0   1   0   1   1                                    
     *  0   0   0   1   0   1  |  1   0   1   1   1   1  |  1   0   1   1   1   1                          
     *    a       a       a    |    a       a       b    |    b       b       b                      
     * 
     */
    libsnark::linear_combination_array<Fr> eq_2_or_3_in(2);
    eq_2_or_3_in[0] = cmp_exp_ab->ret_lt() + cmp_exp_ab->ret_leq() + cmp_man_ab->ret_leq() - 2;
    eq_2_or_3_in[1] = cmp_exp_ab->ret_lt() + cmp_exp_ab->ret_leq() + cmp_man_ab->ret_leq() - 3;
    eq_2_or_3.reset(new grand_product_gadget(pb, eq_2_or_3_in));
    a_lt_b.reset(new zero_gadget(pb, eq_2_or_3->ret()));

    // 指数较大的数为x, 较小的为y
    libsnark::linear_combination_array<Fr> var_a(3);
    libsnark::linear_combination_array<Fr> var_b(3);
    var_a[0] = a.sign;
    var_a[1] = a.exponent;
    var_a[2] = a.mantissa;
    var_b[0] = b.sign;
    var_b[1] = b.exponent;
    var_b[2] = b.mantissa;
    slt_xy.reset(new select_gadget(pb, a_lt_b->ret(), var_b, var_a));

    x_sign = slt_xy->ret(0);
    x_exponent = slt_xy->ret(1);
    x_mantissa = slt_xy->ret(2);

    y_sign =  a.sign + b.sign - x_sign;
    y_exponent = a.exponent + b.exponent - x_exponent;
    y_mantissa = a.mantissa + b.mantissa - x_mantissa;
    
    // 当diff超过M+3, 其实际上的效果等于M+3
    min_exp.reset(new min_gadget(pb, x_exponent - y_exponent, M+3, E+1));
  }

  void generate_r1cs_witness2() {
    // Tick tick(__FN__);
    y_shift->generate_r1cs_witness();
    is_same_sign->generate_r1cs_witness();
    slt_man_add->generate_r1cs_witness();
    debug_add();
  }

  void debug_add(){
  }

  std::shared_ptr<shift_gadget> y_shift;
  std::shared_ptr<xnor_gadget> is_same_sign;
  std::shared_ptr<select_gadget> slt_man_add;
  
  void add_mantissa(){
    Tick tick(__FN__);

    // 将较大的数左移动M+3位, 较小的数左移动M+3-diff位
    libsnark::linear_combination<Fr> x_shift = x_mantissa * Pow2[M+3];
    y_shift.reset(new shift_gadget(pb, y_mantissa, -min_exp->ret()+M+3, misc::Log2UB(M+3)));

    // 根据符号位进行+或者-
    is_same_sign.reset(new xnor_gadget(pb, a.sign, b.sign));
    slt_man_add.reset(new select_gadget(pb, is_same_sign->ret(), x_shift + y_shift->ret(), x_shift - y_shift->ret()));
  }

  void generate_r1cs_witness3() {
    // Tick tick(__FN__);
    pb.val(norm_offset) = 0;
    Fr mantissa = slt_man_add->ret().evaluate(pb.full_variable_assignment());
    if(mantissa != 0)
      for(; mantissa<Pow2[M*2+4]; mantissa*=2, pb.val(norm_offset)+=1);
    shift_man->generate_r1cs_witness();
    zero_man->generate_r1cs_witness();
    pack_man->generate_r1cs_witness();
    // debug_norm();
  }

  void debug_norm(){
    std::cout << "norm_offset:" << pb.val(norm_offset) << "\n";
    std::cout << "shift_man:" << pb.val(shift_man->ret()) << "\n";
  }

  libsnark::pb_variable<Fr> norm_offset;
  std::shared_ptr<shift_gadget> shift_man;
  std::shared_ptr<zero_gadget> zero_man;
  std::shared_ptr<pack_gadget> pack_man;
  void norm_mantissa(){
    Tick tick(__FN__);
    libsnark::linear_combination<Fr> mantissa = slt_man_add->ret();
    
    // norm, 将尾数移动d位使得高位为1, 这里norm的取值应该为[0, M+2]?
    norm_offset.allocate(pb);
    shift_man.reset(new shift_gadget(pb, mantissa, norm_offset, misc::Log2UB(M*2+5)));

    // 证明移动后的尾数高位为1
    // 判断尾数是否为0
    zero_man.reset(new zero_gadget(pb, shift_man->ret()));
    
    // m - (1 << 2m+4)  \in [0, 1 << 2m+4)
    // m - 0  \in [0, 1 << 2m+4)
    pack_man.reset(new pack_gadget(pb, shift_man->ret(), M*2+5));
  }

  void generate_r1cs_witness4() {
    // Tick tick(__FN__);
    zero_sticky->generate_r1cs_witness();
    and_least_round->generate_r1cs_witness();
    slt_carry->generate_r1cs_witness();
    pack_most->generate_r1cs_witness();

    is_overflow->generate_r1cs_witness();
    slt_overflow->generate_r1cs_witness();
    cmp_exp_overflow->generate_r1cs_witness();
    cmp_exp_underflow->generate_r1cs_witness();
    is_ret_zero->generate_r1cs_witness();
    slt_ret_sign->generate_r1cs_witness();
    slt_ret_man->generate_r1cs_witness();
    slt_ret_exp->generate_r1cs_witness();
    ret_abnorm->generate_r1cs_witness();
    // debug_round();
  }

  void debug_round(){
    std::cout << "zero flag:" << is_ret_zero->ret().evaluate(pb.full_variable_assignment()) << "\n";
    std::cout << "zero flag0:" << is_ret_zero->or2->x[0].evaluate(pb.full_variable_assignment()) << "\n";
    std::cout << "zero flag1:" << is_ret_zero->or2->x[1].evaluate(pb.full_variable_assignment()) << "\n";
    std::cout << "zero flag2:" << is_ret_zero->or2->x[2].evaluate(pb.full_variable_assignment()) << "\n";
    std::cout << "zero flag3:" << is_ret_zero->or2->x[3].evaluate(pb.full_variable_assignment()) << "\n";
    std::cout << "zero flag4:" << is_ret_zero->or2->x[4].evaluate(pb.full_variable_assignment()) << "\n";
    std::cout << "exp overflow:" << pb.val(cmp_exp_overflow->ret_leq()) << "\n";
    std::cout << "exp underlow:" << pb.val(cmp_exp_underflow->ret_leq()) << "\n";
    std::cout << "carry:" << slt_carry->ret().evaluate(pb.full_variable_assignment()) << "\n";
    std::cout << "s e m:" << slt_ret_sign->ret().evaluate(pb.full_variable_assignment()) << "\t" 
                          << slt_ret_exp->ret().evaluate(pb.full_variable_assignment())  << "\t"
                          << slt_ret_man->ret().evaluate(pb.full_variable_assignment())  << "\t"
                          << ret_abnorm->ret().evaluate(pb.full_variable_assignment()) << "\n";
  }

  std::shared_ptr<or_gadget> zero_sticky;
  std::shared_ptr<and_gadget> and_least_round;
  std::shared_ptr<select_gadget> slt_carry;
  std::shared_ptr<pack_gadget> pack_most;
  std::shared_ptr<zero_gadget> is_overflow;
  std::shared_ptr<select_gadget> slt_overflow;
  std::shared_ptr<comparison_gadget> cmp_exp_overflow;
  std::shared_ptr<comparison_gadget> cmp_exp_underflow;
  std::shared_ptr<or_gadget> is_ret_zero;
  std::shared_ptr<select_gadget> slt_ret_sign;
  std::shared_ptr<select_gadget> slt_ret_man;
  std::shared_ptr<select_gadget> slt_ret_exp;
  std::shared_ptr<or_gadget> ret_abnorm;
  void round_man(){
    Tick tick(__FN__);
    // 取第M位(0开始), M+1位, 以及M+2到最低位(从左到右)
    libsnark::linear_combination_array<Fr> sticky_bits(M+3);
    for(size_t i=0; i<M+3; i++){
      sticky_bits[i] = pack_man->ret(i);
    }
    zero_sticky.reset(new or_gadget(pb, sticky_bits));
   
    // 如果sticky_bits = 0 则carry等于有效位最后一位 & round_bit
    and_least_round.reset(new and_gadget(pb, pack_man->ret(M+3), pack_man->ret(M+4)));
    slt_carry.reset(new select_gadget(pb, zero_sticky->ret(), pack_man->ret(M+3), and_least_round->ret()));

    // 将前M位打包
    libsnark::linear_combination_array<Fr> most(M+1);
    for(size_t i=0; i<M+1; i++){
      most[i] = pack_man->ret(M+4+i);
    }
    pack_most.reset(new pack_gadget(pb, most));

    // 判断是否越界
    is_overflow.reset(new zero_gadget(pb, pack_most->ret() + slt_carry->ret() - Pow2[M+1]));

    // 更新尾数
    slt_overflow.reset(new select_gadget(pb, is_overflow->ret(), Pow2[M], pack_most->ret() + slt_carry->ret()));

    // 如果尾数为0, 更新指数和符号位为0
    // 如果exp超过范围或者小于等于0, 更新指数和符号位为0
    // 如果存在abnormal, 更新指数和符号位为0
    cmp_exp_underflow.reset(new comparison_gadget(pb, E+1, x_exponent+1+is_overflow->ret(), norm_offset));
    cmp_exp_overflow.reset(new comparison_gadget(pb, E+1, norm_offset+((1<<E)-1+M), x_exponent+1+is_overflow->ret()));

    libsnark::linear_combination_array<Fr> is_ret_zero_in(5);
    is_ret_zero_in[0] = a.abnormal;
    is_ret_zero_in[1] = b.abnormal;
    is_ret_zero_in[2] = zero_man->ret();
    is_ret_zero_in[3] = cmp_exp_overflow->ret_leq();
    is_ret_zero_in[4] = cmp_exp_underflow->ret_leq();
    is_ret_zero.reset(new or_gadget(pb, is_ret_zero_in));

    // 更新指数
    slt_ret_exp.reset(new select_gadget(pb, is_ret_zero->ret(), 0, x_exponent+1+is_overflow->ret()-norm_offset));

    // 更新符号位
    slt_ret_sign.reset(new select_gadget(pb, is_ret_zero->ret(), 0, x_sign));

    // 更新尾数
    slt_ret_man.reset(new select_gadget(pb, is_ret_zero->ret(), 0, slt_overflow->ret()));
    
    // 更新abnorm
    libsnark::linear_combination_array<Fr> ret_abnorm_in(4);
    ret_abnorm_in[0] = a.abnormal;
    ret_abnorm_in[1] = b.abnormal;
    ret_abnorm_in[2] = cmp_exp_overflow->ret_leq();
    ret_abnorm_in[3] = cmp_exp_underflow->ret_leq();
    ret_abnorm.reset(new or_gadget(pb, ret_abnorm_in));

    //
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1, slt_ret_sign->ret(), c.sign)
    );

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1, slt_ret_exp->ret(), c.exponent)
    );

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1, slt_ret_man->ret(), c.mantissa)
    );

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(1, ret_abnorm->ret(), c.abnormal)
    );
  }
  /**
   * a, b必须已经在pb中
   */
  add_gadget(libsnark::protoboard<Fr>& pb,
            float_var const& a,
            float_var const& b,
            float_var const& c,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        a(a), b(b), c(c) {
    Tick tick(__FN__);
    align_exp();
    add_mantissa();
    norm_mantissa();
    round_man();
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
  const std::string path = std::string("/home/dj/work/gitwork/Float/data/f32/add_bak");
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
    gadget.generate_r1cs_witness();
    CHECK(pb.is_satisfied(), "");
  }

  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
  return false;
}
};  // namespace circuit::vgg16