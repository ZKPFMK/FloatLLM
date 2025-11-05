#pragma once

#include "floatvar.h"
#include "select_gadget.h"
#include "shift_gadget.h"
#include "max_gadget.h"
#include "min_gadget.h"
#include "or_gadget.h"
#include "xnor_gadget.h"

namespace circuit::flt {

class add_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * a, b必须已经在pb中
   */
  add_gadget(libsnark::protoboard<Fr>& pb,
            float_var const& a,
            float_var const& b,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        a(a), b(b) {
    c.allocate(pb, this->annotation_prefix);
    
    // 比较指数大小
    libsnark::pb_variable<Fr> less_exp, less_or_eq_exp;
    less_exp.allocate(pb);
    less_or_eq_exp.allocate(pb);
    cmp_exp.reset(new libsnark::comparison_gadget<Fr>(pb, E+1, a.exponent, b.exponent, less_exp, less_or_eq_exp));
    cmp_exp->generate_r1cs_constraints();

    //指数较大的数为x, 较小的为y
    slt_exp.reset(new select_gadget(pb, less_exp, b.exponent, a.exponent));
    libsnark::linear_combination<Fr> x_exponent = slt_exp->ret();
    libsnark::linear_combination<Fr> y_exponent = a.exponent + b.exponent - x_exponent;
    libsnark::linear_combination<Fr> dif = x_exponent - y_exponent;

    slt_man1.reset(new select_gadget(pb, less_exp, b.mantissa, a.mantissa));
    libsnark::linear_combination<Fr> x_mantissa = slt_man1->ret();
    libsnark::linear_combination<Fr> y_mantissa = a.mantissa + b.mantissa - x_mantissa;

    slt_sgn1.reset(new select_gadget(pb, less_exp, b.sign, a.sign));
    libsnark::linear_combination<Fr> x_sign = slt_sgn1->ret();
    libsnark::linear_combination<Fr> y_sign = a.sign + b.sign - x_sign;

    // 当dif超过M+3, 其实际上的效果等于M+3
    // continue
    libsnark::pb_linear_combination<Fr> lc_dif, lc_m3;
    lc_dif.assign(pb, dif);
    lc_m3.assign(pb, M+3);
    min.reset(new min_gadget(pb, lc_dif, lc_m3, E+1));
    libsnark::linear_combination<Fr> abs = min->ret();

    // 将较大的数左移动abs位
    libsnark::pb_linear_combination<Fr> lc_abs;
    lc_abs.assign(pb, abs);
    libsnark::pb_variable<Fr> x_mantissa_shift;
    shf.reset(new shift_gadget(pb, lc_abs, E+1));
    libsnark::linear_combination<Fr> pow2_abs = shf->ret();
    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(pow2_abs, x_mantissa, x_mantissa_shift)
    );

    // 比较尾数大小
    libsnark::pb_linear_combination<Fr> lc_x_mantissa;
    libsnark::pb_linear_combination<Fr> lc_y_mantissa;
    lc_x_mantissa.assign(pb, x_mantissa);
    lc_y_mantissa.assign(pb, y_mantissa);

    libsnark::pb_variable<Fr> less_man, less_or_eq_man;
    less_man.allocate(pb);
    less_or_eq_man.allocate(pb);
    cmp_man.reset(new libsnark::comparison_gadget<Fr>(pb, M+1, lc_y_mantissa, lc_x_mantissa, less_man, less_or_eq_man));
    cmp_man->generate_r1cs_constraints();
    
    or_gat.reset(new or_gadget(pb, less_man, less_exp));   
    libsnark::pb_linear_combination<Fr> man_geq;
    man_geq.assign(pb, or_gat->ret());
    slt_man2.reset(new select_gadget(pb, man_geq, x_mantissa_shift, lc_y_mantissa));
    libsnark::linear_combination<Fr> xx_mantissa = slt_man2->ret();
    libsnark::linear_combination<Fr> yy_mantissa = x_mantissa_shift + lc_y_mantissa - xx_mantissa;

    libsnark::pb_linear_combination<Fr> lc_x_sign, lc_y_sign;
    lc_x_sign.assign(pb, x_sign);
    lc_y_sign.assign(pb, y_sign);
    slt_sgn2.reset(new select_gadget(pb, man_geq, lc_x_sign, lc_y_sign));
    libsnark::linear_combination<Fr> xx_sign = slt_man2->ret();
    
    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(FrOne(), xx_sign, c.sign)
    );

    // xnor_gat.reset(new xnor_gadget(pb, x_sign, y_sign));
    // slt_man3.reset(new select_gadget(pb, xnor_gat->ret(), xx_mantissa + yy_mantissa, xx_mantissa - yy_mantissa));

    //continue round
    // 符号相同则尾数相加

    // 符号不同则尾数相减少

    //continue
  }

  float_var ret() const { return c; }

  void Assign(std::array<Fr const*, 9> const& data,
              std::array<Fr const*, 9> const& para) {
    // std::vector<Fr> vec_data(9);
    // std::vector<Fr> vec_para(9);
    // for (size_t i = 0; i < 9; ++i) {
    //   vec_data[i] = *data[i];
    //   vec_para[i] = *para[i];
    // }
    // data_.fill_with_field_elements(this->pb, vec_data);
    // para_.fill_with_field_elements(this->pb, vec_para);
    // ip_->generate_r1cs_witness();
  }

private:
  std::shared_ptr<libsnark::comparison_gadget<Fr>> cmp_exp;
  std::shared_ptr<libsnark::comparison_gadget<Fr>> cmp_man;
  std::shared_ptr<max_gadget> max;
  std::shared_ptr<min_gadget> min;
  std::shared_ptr<or_gadget> or_gat;
  std::shared_ptr<xnor_gadget> xnor_gat;
  std::shared_ptr<select_gadget> slt_exp;
  std::shared_ptr<select_gadget> slt_man1;
  std::shared_ptr<select_gadget> slt_man2;
  std::shared_ptr<select_gadget> slt_man3;
  std::shared_ptr<select_gadget> slt_sgn1;
  std::shared_ptr<select_gadget> slt_sgn2;
  std::shared_ptr<shift_gadget> shf;
  float_var const& a;
  float_var const& b;
  float_var c;
};

inline bool TestAdd() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, y;
  libsnark::pb_variable<Fr> less, less_or_eq;

  x.allocate(pb, "x");
  y.allocate(pb, "y");
  less.allocate(pb, "less");
  less_or_eq.allocate(pb, "less_or_eq");
  libsnark::comparison_gadget<Fr> cmp(pb, 3, x, y, less, less_or_eq, "cmp");
  cmp.generate_r1cs_constraints();
  pb.val(x) = 3;
  pb.val(y) = 3;
  cmp.generate_r1cs_witness();
  std::cout << "less:" << pb.val(x) << "\t" << pb.val(y) << "\t" << pb.val(less) << "\t" << pb.val(less_or_eq) << "\n";

//   libsnark::test_comparison_gadget<Fr>(2);
  return false;
}
};  // namespace circuit::vgg16