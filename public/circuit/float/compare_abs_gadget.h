#pragma once

#include "floatvar.h"
#include "circuit/select_gadget.h"
#include "circuit/compare_gadget.h"
#include "circuit/grand_product_gadget.h"
// 49 => 41
namespace circuit::flt {
class compare_abs_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:e \in {0, 1}^E, m \in {0, 1}^{M+1}
   * 返回 (man1 << exp1) <= (man2 << exp2) ? 1 : 0
   */
  compare_abs_gadget(libsnark::protoboard<Fr>& pb,
                     libsnark::linear_combination<Fr> const& sign1,
                     libsnark::linear_combination<Fr> const& sign2,
                     libsnark::linear_combination<Fr> const& exp1,
                     libsnark::linear_combination<Fr> const& exp2,
                     libsnark::linear_combination<Fr> const& man1,
                     libsnark::linear_combination<Fr> const& man2,
                     const std::string& annotation_prefix = "")
      : sign1(sign1), sign2(sign2), exp1(exp1), exp2(exp2), man1(man1), man2(man2),
        libsnark::gadget<Fr>(pb, annotation_prefix) {
    
    cmp.reset(new comparison_gadget(pb, E+M+2, exp1*Pow2[M+1]+man1, exp2*Pow2[M+1]+man2));

    // 比较指数大小
    // cmp_exp.reset(new comparison_gadget(pb, E+1, exp1, exp2));

    // 比较尾数大小
    // cmp_man.reset(new comparison_gadget(pb, M+1, man1, man2));

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
    // libsnark::linear_combination_array<Fr> eq_23_in(2);
    // eq_23_in[0] = cmp_exp->ret_lt() + cmp_exp->ret_leq() + cmp_man->ret_leq() - 2;
    // eq_23_in[1] = cmp_exp->ret_lt() + cmp_exp->ret_leq() + cmp_man->ret_leq() - 3;
    // eq_23.reset(new grand_product_gadget(pb, eq_23_in));

    // a < b
    // lt.reset(new zero_gadget(pb, eq_23->ret()));

    // a < b ? b : a
    libsnark::linear_combination_array<Fr> f1(3);
    libsnark::linear_combination_array<Fr> f2(3);
    f1[0] = sign1;
    f2[0] = sign2;
    f1[1] = exp1;
    f2[1] = exp2;
    f1[2] = man1;
    f2[2] = man2;
    max.reset(new select_gadget(pb, cmp->ret_lt(), f2, f1));
  }

  void generate_r1cs_witness() {
    // cmp_exp->generate_r1cs_witness();
    // cmp_man->generate_r1cs_witness();
    // eq_23->generate_r1cs_witness();
    // lt->generate_r1cs_witness();
    cmp->generate_r1cs_witness();
    max->generate_r1cs_witness();
  }

  libsnark::linear_combination<Fr> ret_sign() const { return max->ret(0); }
  libsnark::linear_combination<Fr> ret_exp() const { return max->ret(1); }
  libsnark::linear_combination<Fr> ret_man() const { return max->ret(2); }

  // std::shared_ptr<grand_product_gadget> eq_23;
  std::shared_ptr<comparison_gadget> cmp;
  // std::shared_ptr<comparison_gadget> cmp_exp;
  // std::shared_ptr<comparison_gadget> cmp_man;
  std::shared_ptr<select_gadget> max;
  // std::shared_ptr<zero_gadget> lt;
public:
  libsnark::linear_combination<Fr> const sign1;
  libsnark::linear_combination<Fr> const sign2;
  libsnark::linear_combination<Fr> const exp1;
  libsnark::linear_combination<Fr> const exp2;
  libsnark::linear_combination<Fr> const man1;
  libsnark::linear_combination<Fr> const man2;
};

inline bool TestCmpAbsGadget() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> s1, s2;
  libsnark::pb_variable<Fr> e1, e2;
  libsnark::pb_variable<Fr> m1, m2;
  s1.allocate(pb);
  s2.allocate(pb);
  e1.allocate(pb);
  e2.allocate(pb);
  m1.allocate(pb);
  m2.allocate(pb);
  compare_abs_gadget gadget(pb, s1, s2, e1, e2, m1, m2);
  for(size_t i=0; i<2; i++){
    for(size_t j=0; j<2; j++){
      pb.val(e1) = i;
      pb.val(m1) = i;
      pb.val(e2) = j;
      pb.val(m2) = j;
      gadget.generate_r1cs_witness();
      CHECK( (i << i) <= (j << j) ? j : i == gadget.ret_exp().evaluate(pb.full_variable_assignment()).getInt64(), "");
    }
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}
}  // namespace circuit::fixed_point