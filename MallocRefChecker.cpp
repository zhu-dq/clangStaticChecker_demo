/*
 *  主要检测内存分配相关工作
 *  1.禁止使用未初始化函数
 *  2.内存分配后立即跟判空操作
 *  3.初始化范围要合法
*/
#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "llvm/Support/Casting.h"
#include <cmath>
#include <list>
#include <iostream>
#include <fstream>
#include  <sstream>
#include <string>
#include <vector>
#include <map>
 #include "Logging.h"
#include "LogStream.h"
#include "Timestamp.h"
 #include "checker.h"
using namespace std;
using namespace clang;
using namespace ento;
using namespace nonloc;

#define GETUONAME(expr)																					\
		if ((expr) && (expr)->getCastKindName() == "PointerToBoolean")									\
		{																								\
			const ImplicitCastExpr * ILCER = dyn_cast<ImplicitCastExpr>((expr)->getSubExpr());			\
			if(ILCER)																					\
			{																							\
				const DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(ILCER->getSubExpr());					\
				if (DRE)																				\
				{																						\
						const ValueDecl* VD = DRE->getDecl();											\
						if (VD)																			\
						{																				\
							int VDLoc = 0;																\
							std::string VDName = "";													\
							VDLoc = VD->getLocStart().getRawEncoding();									\
							if(!checknullmap.count(VDLoc))												\
							{																			\
								checknullmap.insert(make_pair(VDLoc,1));								\
							}																			\
						}																				\
				}																						\
			}																							\
		}

namespace {
	/*
		MallocNodeParam类
		存储内存分配函数的配置信息
	*/
	class  MallocNodeParam
	{
		private:
			mutable vector<int> ArgLocation;
			mutable bool flag;
			mutable bool HasArg;
		public:
			MallocNodeParam():flag(false),HasArg(false){}
			bool IsInit()const
			{
				return flag;
			}
			void SetInit()const
			{
				flag = true;
			}
			bool IsHasParam()const
			{
				return HasArg;
			}
			void SetArgHas()const
			{
				HasArg = true;
			}
			void SetArgLocation(int param)const
			{
				ArgLocation.push_back(param);
			}
			vector<int> GetArgLocations()const
			{
				return ArgLocation;
			}

	};
	class  MallocRefChecker:public Checker<
						 check::Location,
						 check::ASTDecl<FunctionDecl>,
						 check::BranchCondition,
						 check::Bind,
						 check::PreCall>{
	private:
		mutable std::unique_ptr<BugType> BT_valueerror;  
		 mutable std::unique_ptr<BugType> BT;									//	UnInitChecker
		 mutable map<unsigned int, std::string> CheckedValueDecls;				//	存储做过范围判断的变量
		 mutable map<unsigned int,  int > CheckedInitDecls;						//	存储已经初始化的变量
		 mutable map<string,MallocNodeParam>mallocmap;							//	存储内存分配函数
		 mutable  map<string,vector<string>>initmap;							//	存储内存初始化函数
		 mutable map<unsigned int,int>ptrmap;									//	存储是否进行判空操作  0.表示没有进行判空操作  1.表示已经进行判空
		 mutable map<unsigned int, int>checknullmap;							//	存储做了判空操作的指针变量VDLoc
		 mutable unsigned long CallBackFunctionRunTime;
	public:
		/*
			读入配置文件信息
		*/
		MallocRefChecker();
		~MallocRefChecker()
		{
			LOG_INFO << "MallocRefChecker*" << CallBackFunctionRunTime;
		}
		/*
			针对C4.5
			针对内存分配函数的参数不确定时，
			检查是否对未确定的参数做过判断
		*/
		void checkBranchCondition(const Stmt* S, CheckerContext& C) const;
		/*
			针对 C4.1
			检查是否使用未初始化的变量
		*/
		void checkBind(SVal location, SVal val,const Stmt *StoreE,CheckerContext &C) const ;
		/*
			针对	 C4.6
			检查指针变量在使用前是否进行了判空操作
		*/
		 void checkLocation(SVal loc, bool IsLoad, const Stmt* S,CheckerContext& ctx) const;
		 /*
			针对 C4.6
			报错：指针使用时没有进行判空操作
		 */
		void ReporterrValue1(CheckerContext &C)const;
		/*
			checkBind的辅助函数
			确定是否内存分配函数
		*/
		void  getCallExpr(unsigned int  *l_name,int* flag1,int* flag2,int* flag3,const  Stmt * S)const;
		/*
				遍历查找，获取指针变量名字
		*/
		void  testLocation(unsigned int *declname,int *flag0,int *flag1,const  Stmt *S)const;
		void  testLocation1(unsigned int *declname, int *flag0, int *flag1, const  Stmt *S)const;
		void  testLocation0(const  Stmt *S)const;
		/*
			checkASTDecl的实际执行函数
		*/
		void  testCheckNullStmt(const Stmt * S)const;
		/*
			针对C4.6的辅助函数
			预先遍历ast树，存储做过判空的指针变量
		*/
		void checkASTDecl(const FunctionDecl *FD, AnalysisManager& mgr, BugReporter &BR) const;
		/*
			针对C4.1的辅助函数
			查看=右边是否存在没有初始化的变量
		*/
		void  test_R_Bind(int *initflag,const Stmt *S)const;
		/*
			针对C4.5
			检查内存分配函数的参数是否合法
		*/

		void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
		/*
			C4.5报错函数:参数大小不合法
		*/
		void ReporterrValue(CheckerContext &C)const;
		/*
			报错函数：警告：参数不确定或是个非整数函数
		*/
		void ReportwarnValue(CheckerContext &C)const;
	};
}
MallocRefChecker::MallocRefChecker(){
	CallBackFunctionRunTime = 0;
	if(!BT_valueerror)
		{BT_valueerror.reset(new BugType(this,"MallocRefChecker", "Memory Error"));}
	/*
		config
	*/
	const auto& config=checker_doc::instance();
	auto v =  config.checker_config.at("c4.1").functions_list.at("memAllocFuncs");
	for( auto& elem : v )
	{
		MallocNodeParam inode;
		if(atoi(elem.option_list["isInit"].c_str())==1)
			inode.SetInit();
		auto vfuncpara = elem.function_parameters;
		for (auto& item : vfuncpara)
		{
			if (item.pos < 0)
				continue;
			inode.SetArgHas();
			inode.SetArgLocation(item.pos);
		}
		mallocmap.insert(make_pair(elem.name,inode));
	}
	auto vinit =  config.checker_config.at("c4.1").functions_list.at("memInitFuncs");
	for(auto& elem : vinit)
	{
		vector<string> vlocation;
		auto vfuncpara = elem.function_parameters;
		for(auto& item : vfuncpara )
			vlocation.push_back(std::to_string(item.pos));
		initmap.insert(make_pair(elem.name,vlocation));
					
	}
	//cout << "config complish" << endl;
}
void MallocRefChecker::ReporterrValue(CheckerContext &C)const{
	/*
	ExplodedNode *ErrNode = C.generateSink();
	if (!ErrNode){return;}
	BugReport *R = new BugReport(*BT_valueerror, "error : the value is negative number", ErrNode);
	C.emitReport(R);
	*/
	ProgramStateRef State = C.getState();
	ExplodedNode *ErrNode = C.addTransition(State);
	if (!ErrNode){ return; }
	// BugReport *R = new BugReport(*BT_valueerror, "error : the value is Error number", ErrNode);
	BugReport *R = new BugReport(*BT_valueerror, "error : Validate the integer that indicates the specific requested memory size", ErrNode);
	C.emitReport(R);
}
void MallocRefChecker::ReporterrValue1(CheckerContext &C)const{
	ProgramStateRef State = C.getState();
	ExplodedNode *ErrNode = C.addTransition(State);
	if (!ErrNode){ return; }
	BugReport *R = new BugReport(*BT_valueerror, "error : It must be judged null pointer before use", ErrNode);
	C.emitReport(R);
}
void MallocRefChecker::ReportwarnValue(CheckerContext &C)const{
	ProgramStateRef State = C.getState();
	 ExplodedNode *ErrNode = C.addTransition(State);
	if (!ErrNode){return;}
	BugReport *R = new BugReport(*BT_valueerror, "warning : the value is Uncertain Number or  un-integer", ErrNode);
	C.emitReport(R);
}
void MallocRefChecker::testCheckNullStmt(const Stmt * S)const
{
	if (!S)
		return;
	if (ImplicitCastExpr::classof(S))
	{
		const ImplicitCastExpr * ICEXPR = dyn_cast<ImplicitCastExpr>(S);
		GETUONAME(ICEXPR)
	}
	if (BinaryOperator::classof(S))
	{
			const BinaryOperator* BO = dyn_cast<BinaryOperator>(S);
			/*if ((int)BO->getOpcode() != 13)
				return;*/
			if (
				BO->getOpcodeStr() != "==" &&
				BO->getOpcodeStr() != "!="
				)
				return;
			const Expr* LHSExpr = BO->getLHS();
			const Expr* RHSExpr = BO->getRHS();
			const ImplicitCastExpr* LHSICE = dyn_cast<ImplicitCastExpr>(LHSExpr);
			const ImplicitCastExpr* RHSICE = dyn_cast<ImplicitCastExpr>(RHSExpr);
			if (
				(!LHSICE) ||
				(!RHSICE)
				)
				return;
			const DeclRefExpr* LHSDRE = dyn_cast<DeclRefExpr>(LHSICE->getSubExpr());
			const DeclRefExpr* RHSDRE = dyn_cast<DeclRefExpr>(RHSICE->getSubExpr());
			if (
				(!LHSDRE) &&
				(!RHSDRE)
				)
				return;
#define GETNAME(expr)										\
	const ValueDecl* VD = (expr)->getDecl();				\
	if(!VD)													\
		return ;											\
	VDLoc = VD->getLocStart().getRawEncoding();				\
	VDName = VD->getNameAsString();							\
	PTRNAME = true;
#define GETTYPE(expr)																	\
	if (!((expr)->getCastKindName() == "NullToPointer"))								\
		return ;																		\
	PTRTYPE = true;

		bool PTRTYPE = false;
		bool PTRNAME = false;
		unsigned int VDLoc = 0;
		std::string VDName = "";
		if (LHSDRE)
		{
			GETNAME(LHSDRE)
			GETTYPE(RHSICE)
		}
		else 
		{
			GETNAME(RHSDRE)
			GETTYPE(LHSICE)
		}
		if (PTRNAME && PTRTYPE)
			checknullmap.insert(make_pair(VDLoc,1));
	}
	if (!(S->children()))
		return;
	for (Expr::const_child_iterator child = S->child_begin(); child != S->child_end(); child++){
		testCheckNullStmt((*child));
	}
}
void MallocRefChecker::checkASTDecl(const FunctionDecl *FD, AnalysisManager &mgr, BugReporter &BR) const
{
// 用于计时
	int startTime = Timestamp::now();

	testCheckNullStmt(FD->getBody());
	// 用于计时
	int endTime = Timestamp::now();
	CallBackFunctionRunTime = CallBackFunctionRunTime + endTime - startTime;
}
void MallocRefChecker::checkPreCall(const CallEvent &Call, CheckerContext &C)const{

	// 用于计时
	int startTime = Timestamp::now();

	const IdentifierInfo * name1=Call.getCalleeIdentifier ();
	if (!name1)
		return;
	string  str =name1->getName().str();
	if(initmap.count(str)){
		vector<string> v_arg=initmap[str];
		for(vector<string>::iterator i=v_arg.begin();i!=v_arg.end();i++){
			int  arg_i=atoi((*i).c_str());
			unsigned int declname;
			int flag0 = 0;
			int flag1 = 0;
			testLocation(&declname,&flag0, &flag1, Call.getArgExpr(arg_i));
			if(flag1==1){
				CheckedInitDecls.insert(make_pair(declname, 1));
			}

		}
	}
	if(mallocmap.count(str)){
		vector<int> v_arg = mallocmap[str].GetArgLocations();
		for(vector<int>::iterator i=v_arg.begin();i!=v_arg.end();i++)
		{
			int arg_i = (*i); 
			SVal sval=Call.getArgSVal(arg_i);	
			if(!sval.isConstant())
			{
				unsigned int   declname;							//存储指针变量的名字
				int flag0 = 0;
				int  flag1 = 0;										//判断是否获取到指针变量
				const Expr * E = Call.getArgExpr(arg_i);
				string str = E->getType().getAsString();
				testLocation(&declname,&flag0,&flag1,E);
				if(flag1!=1){
					if (flag0 == 0)
					{
						if (str == "size_t")
							return;
						ReportwarnValue(C);		
					}
					return;	
				}
				if(flag1==1){
					if(!CheckedValueDecls.count(declname)){
						if (flag0 == 0)
						{
							if (str == "size_t")
								return;
							ReportwarnValue(C);		
						}
						return;	
					}
				}	
				continue;		
			}		
			int base =sval.getBaseKind(); 	
			if(base==3){					
				ConcreteInt   ct = sval.castAs<ConcreteInt>();		
				long  int  d= ct.getValue().getSExtValue();			
				if(d<=0)	{							
					ReporterrValue(C);				
				}							
			}else{ReportwarnValue(C);}								
		}
	}

	// 用于计时
	int endTime = Timestamp::now();
	CallBackFunctionRunTime = CallBackFunctionRunTime + endTime - startTime;
}
void MallocRefChecker::getCallExpr(unsigned int * l_name,int* flag1,int* flag2,int *flag3,const  Stmt * S)const
{
	if (!S)
		return;
	 if (DeclStmt::classof(S)){
		const DeclStmt*   declStmt  =  dyn_cast<DeclStmt>(S);
		if (!declStmt)
			return;
		if (!declStmt->isSingleDecl())
			return;
		const VarDecl* varDecl=dyn_cast<VarDecl>( declStmt->getSingleDecl ());
		if(varDecl){
			*l_name = varDecl->getLocStart().getRawEncoding();
			*flag1 = 1;
		}
	}
	 if (CallExpr::classof(S)){
		 const CallExpr* ce = dyn_cast<CallExpr >(S);
		 if (!ce)
			 return;
		 const FunctionDecl * f=ce->getDirectCallee();
		 if (!f)
			return;
			 string  rname= f->getNameAsString();
			 if(mallocmap.count(rname))
			 {
				*flag2 = 1;
				if(mallocmap[rname].IsInit())
					*flag3 = 1;
			 }
	 }
	  if (DeclRefExpr::classof(S)){
		const  DeclRefExpr * declRefExpr=dyn_cast<DeclRefExpr>(S);
		if (!declRefExpr)
			return;
		const  ValueDecl *   valueDecl = declRefExpr->getDecl();
		if (!valueDecl)
			return;
		 *l_name = valueDecl->getLocStart().getRawEncoding();
		 *flag1 = 1;
	  }
	  if((*flag1==1)&&(*flag2==1))
		return ;
	  if (!(S->children()))
		  return;
	for(Expr::const_child_iterator child=S->child_begin();child!=S->child_end();child++){
		getCallExpr(l_name,flag1,flag2,flag3,(*child));
	}
}

void  MallocRefChecker::test_R_Bind(int * initflag,const Stmt *S)const{
	if (!S)
		return;
	if(DeclRefExpr::classof(S)){
		const DeclRefExpr *drexpr = dyn_cast<DeclRefExpr>(S);
		if (!drexpr)
			return;
		const ValueDecl * vdecl =drexpr->getDecl();
		if (!vdecl)
			return;
		unsigned int initname = vdecl->getLocStart().getRawEncoding();
		if(!CheckedInitDecls.count(initname)){
			*initflag=2;
		}
	}
	if (!(S->children()))
		return;
	for(Expr::const_child_iterator child=S->child_begin();child!=S->child_end();child++){
			test_R_Bind(initflag,(*child));
	}
}

void MallocRefChecker::testLocation(unsigned int *declname,int * flag0 ,int * flag1,const Stmt * S)const
{
	if (!S)
		return;
	  if (DeclRefExpr::classof(S)){
		 const  DeclRefExpr * declRefExpr=dyn_cast<DeclRefExpr>(S);
		 if (!declRefExpr)
			 return;
		 const  ValueDecl *   valueDecl = declRefExpr->getDecl();
		 if (!valueDecl)
			 return;
		 *declname = valueDecl->getLocStart().getRawEncoding();
		 if (CheckedValueDecls.count(*declname))
		 {
			 *flag0 = 1;
		 }
		 *flag1 = 1;
	  }
	  if((*flag1==1)&&(*flag0==1))
		return ;
	  if (!(S->children()))
		  return;
	for(Expr::const_child_iterator child=S->child_begin();child!=S->child_end();child++){
		testLocation(declname,flag0, flag1, (*child));
	}
}
void MallocRefChecker::testLocation1(unsigned int *declname, int * flag0, int * flag1, const Stmt * S)const
{
	if (!S)
		return;
	if (DeclRefExpr::classof(S)){
		const  DeclRefExpr * declRefExpr = dyn_cast<DeclRefExpr>(S);
		if (!declRefExpr)
			return;
		const  ValueDecl *   valueDecl = declRefExpr->getDecl();
		if (!valueDecl)
			return;
		*declname = valueDecl->getLocStart().getRawEncoding();
		if (CheckedValueDecls.count(*declname))
		{
			*flag0 = 1;
		}
		*flag1 = 1;
	}
	if ((*flag1 == 1) && (*flag0 == 1))
		return;
	if (!(S->children()))
		return;
	for (Expr::const_child_iterator child = S->child_begin(); child != S->child_end(); child++){
		testLocation1(declname, flag0, flag1, (*child));
	}
}
void MallocRefChecker::testLocation0(const Stmt * S)const
{
	if (!S)
		return;
	if (DeclRefExpr::classof(S)){
		const  DeclRefExpr * declRefExpr = dyn_cast<DeclRefExpr>(S);
		if (!declRefExpr)
			return;
		const  ValueDecl *   valueDecl = declRefExpr->getDecl();
		if (!valueDecl)
			return;
		unsigned int declname = valueDecl->getLocStart().getRawEncoding();
		string name = valueDecl->getNameAsString();
		if (!CheckedValueDecls.count(declname))
		{
			CheckedValueDecls.insert(make_pair(declname, name));
		}
	}
	if (!(S->children()))
		return;
	for (Expr::const_child_iterator child = S->child_begin(); child != S->child_end(); child++){
		testLocation0((*child));
	}
}
void MallocRefChecker::checkBind(SVal location, SVal val,const Stmt *StoreE,CheckerContext &C) const 
{

	// 用于计时
	int startTime = Timestamp::now();

	unsigned int lname;														//  获取左值
	int flag1 = 0;  														//	判断释放获取到左值
	int flag2 = 0;															//	判断内存分配函数
	int flag3 = 0;															//	判断是否初始化 
	getCallExpr(&lname,&flag1,&flag2,&flag3,StoreE);
	if((flag1==1)&&(flag2==1)){
		 ptrmap.insert(make_pair(lname,0));
	}
	 //UnInitChecker
	//Right
	int initflag = 0;
	if(BinaryOperator::classof(StoreE)){
		initflag = 1;
		const BinaryOperator* BO = dyn_cast<BinaryOperator>(StoreE);
		if (!BO)
			return;
		test_R_Bind(&initflag, BO->getRHS());
	}
	//Light
	const MemRegion * mem = location.getAsRegion();
	if (!mem)
		return;
	if (VarRegion::classof(mem)) 
	{
		const VarRegion* dr = static_cast<const VarRegion*>(mem);
		if (!dr)
			return;
		const VarDecl* decl = dr->getDecl();
		if (!decl)
			return;
		unsigned int bindName	=decl->getLocStart().getRawEncoding();//source
		if(!CheckedInitDecls.count(bindName))
		{
			CheckedInitDecls.insert(make_pair(bindName,1));
		}
	}
	if (initflag == 1)
			return;
	if (!val.isUndef())  
			return;
	// Do not report assignments of uninitialized values inside swap functions.
	// This should allow to swap partially uninitialized structs
	// (radar://14129997)
	if (const FunctionDecl *EnclosingFunctionDecl =dyn_cast<FunctionDecl>(C.getStackFrame()->getDecl()))
			if (C.getCalleeName(EnclosingFunctionDecl) == "swap")
				return;
	ExplodedNode *N = C.generateSink();
	if (!N)
			return;
		
	const char *str = "use uninit or undefined";
	if (!BT)
			BT.reset(new BuiltinBug(this, str));
	// Generate a report for this bug.
	const Expr *ex = nullptr;
	while (StoreE) {
			if (const BinaryOperator *B = dyn_cast<BinaryOperator>(StoreE)) {
				if (B->isCompoundAssignmentOp()) {
						ProgramStateRef state = C.getState();
						if (state->getSVal(B->getLHS(), C.getLocationContext()).isUndef()) {
							str = "The left expression of the compound assignment is an "
								"uninitialized value. The computed value will also be garbage";
							ex = B->getLHS();
							break;
						}
				 }
				ex = B->getRHS();
				break;
			}

			if (const DeclStmt *DS = dyn_cast<DeclStmt>(StoreE)) {
			if (!DS->isSingleDecl())
					return;
			const VarDecl *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
				if (!VD)
					return;
				ex = VD->getInit();
			}
			break;
	}

	BugReport *R = new BugReport(*BT, str, N);
	if (ex) {
			R->addRange(ex->getSourceRange());
			bugreporter::trackNullOrUndefValue(N, ex, *R);
	}
	C.emitReport(R);


	// 用于计时
	int endTime = Timestamp::now();
	CallBackFunctionRunTime = CallBackFunctionRunTime + endTime - startTime;

}
void MallocRefChecker::checkBranchCondition(const Stmt* S, CheckerContext &C) const
{
	// 用于计时
	int startTime = Timestamp::now();

	const Expr* E = dyn_cast<Expr>(S);
	if (!E)
		return;
	if (ImplicitCastExpr::classof(E))
	{
		const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(E);
		GETUONAME(ICE)
	}
	if (UnaryOperator::classof(E))
	{
		const UnaryOperator *UO = dyn_cast<UnaryOperator>(E);
		if (UO->getOpcode() == 9)	//9 : !
		{
			const ImplicitCastExpr * ICER = dyn_cast<ImplicitCastExpr>(UO->getSubExpr());
			GETUONAME(ICER)
		}

	}
	const BinaryOperator* B = dyn_cast<BinaryOperator>(E);
	if (!B)
		return;
	if (B->getOpcodeStr() != "<" && 
			B->getOpcodeStr() != ">" &&
			B->getOpcodeStr() != ">=" &&
			B->getOpcodeStr() != "<=")
		return;
	const Expr* LHSExpr = B->getLHS();
	const Expr* RHSExpr = B->getRHS();
	testLocation0(LHSExpr);
	testLocation0(RHSExpr);
	const ImplicitCastExpr* LHSICE = dyn_cast<ImplicitCastExpr>(LHSExpr);
	const ImplicitCastExpr* RHSICE = dyn_cast<ImplicitCastExpr>(RHSExpr);

#define SAVE_INFO(side)																						\
	if (side##HSICE)																						\
	{																										\
		const DeclRefExpr* side##HSDRE = dyn_cast<DeclRefExpr>(side##HSICE->getSubExpr());					\
		if (side##HSDRE)																					\
		{																									\
			const ValueDecl* VD = side##HSDRE->getDecl();													\
			if (!VD)																						\
				return;																						\
			unsigned int VDLoc = VD->getLocStart().getRawEncoding();										\
			std::string VDName = VD->getNameAsString();														\
			if(!CheckedValueDecls.count(VDLoc))																\
				CheckedValueDecls.insert(make_pair(VDLoc, VDName));											\
		}																									\
		else																								\
		{																									\
			const ImplicitCastExpr* side##HSICEICE = dyn_cast<ImplicitCastExpr>(side##HSICE->getSubExpr());	\
			if (side##HSICEICE)																				\
			{																								\
				const DeclRefExpr* side##HSDRE = dyn_cast<DeclRefExpr>(side##HSICEICE->getSubExpr());		\
				if (side##HSDRE)																			\
				{																							\
					const ValueDecl* VD = side##HSDRE->getDecl();											\
					if (!VD)																				\
						return;																				\
					unsigned int VDLoc = VD->getLocStart().getRawEncoding();								\
					std::string VDName = VD->getNameAsString();												\
					if(!CheckedValueDecls.count(VDLoc))														\
						CheckedValueDecls.insert(make_pair(VDLoc, VDName));									\
				}																							\
			}																								\
		}																									\
	}																										
	SAVE_INFO(L);
	SAVE_INFO(R);

	// 用于计时
	int endTime = Timestamp::now();
	CallBackFunctionRunTime = CallBackFunctionRunTime + endTime - startTime;
}
void MallocRefChecker::checkLocation(SVal loc, bool IsLoad, const Stmt* S,CheckerContext& ctx)const{
	// 用于计时
	int startTime = Timestamp::now();
	unsigned int   declname;											//存储指针变量的名字
	int flag0 = 0;
	int  flag1 = 0;														//判断是否获取到指针变量名字
	testLocation(&declname,&flag0,&flag1,S);
	if (flag1 == 1)
	{
		if (	(ptrmap.count(declname)) &&
				(ptrmap[declname]==0)
			)
		{
			if ((checknullmap.count(declname)))
			{
				return;
			}
			else
			{
				ReporterrValue1(ctx);
				ptrmap[declname] = 1;
				return;
			}
		}
	}
	// 用于计时
	int endTime = Timestamp::now();
	CallBackFunctionRunTime = CallBackFunctionRunTime + endTime - startTime;
}
void ento::registerMallocRefChecker(CheckerManager &mgr) {
	mgr.registerChecker<MallocRefChecker>();
}