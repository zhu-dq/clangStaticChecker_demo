/*
这是个内存释放相关checker。包含以下checker:
C4.2:禁止访问已经释放的checker
C4.3:禁止重复释放内存
C4.4:指针释放之后立即赋予新值
chekcer命名为FreeRef
*/

#include "ClangSACheckers.h"
#include "InterCheckerAPI.h"
#include "clang/AST/Attr.h"
#include "clang/AST/ParentMap.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "llvm/ADT/ImmutableMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/Casting.h"
#include <climits>
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

namespace {
	/*
	为内置MAP设计的属性类
	*/
	struct FuncString{
		string fName;
		FuncString(string Name){
			fName = Name;
		}
		bool operator==(const FuncString &X)const {
			return fName == X.fName;
		}
		bool operator<(const FuncString &X)const {
			return fName<X.fName;
		}

		void Profile(llvm::FoldingSetNodeID &ID) const {
			StringRef fNameRef = StringRef(fName);
			ID.AddString(fNameRef);
		}

	};
	/*
	控制检查是否存在free函数
	*/
	class CheckFreeNode
	{
	private:
		mutable bool IsL;
		mutable bool IsNull;
		mutable bool IsRightName;
		mutable string grandfather;
	public:
		CheckFreeNode()
		{
			IsL = false;
			IsNull = false;
			IsRightName = false;
			grandfather = "undef";
		}
		void setIsNull()const
		{
			IsNull = true;
		}
		void setIsL()const
		{
			IsL = true;
		}
		void setIsRightName()const
		{
			IsRightName = true;
		}
		bool getIsNull()const
		{
			return IsNull;
		}
		bool getIsL()const
		{
			return IsL;
		}
		bool getIsRightName()const
		{
			return IsRightName;
		}
		void setGrandFather(string classname)const
		{
			grandfather = classname;
		}
		string getGrandFather()const
		{
			return grandfather;
		}
	};
	class  CheckNode
	{
	private:
		mutable int flag;
		mutable  int cnt;
		mutable unsigned int name;
		mutable string funcname;
		mutable string backfunc;
	public:
		CheckNode() :flag(0), cnt(0), name(0)
		{
			funcname = "";
			backfunc = "";
		}
		void on()const
		{
			flag = 1;
		}
		void off()const
		{
			flag = 0;
			cnt = 0;
			name = 0;
			funcname = "";
		}
		void setcount()const
		{
			cnt = this->cnt + 1;
		}
		int getcount()const
		{
			return cnt;
		}
		void setname(unsigned int LOC)const
		{
			name = LOC;
		}
		unsigned int getname()const
		{
			return name;
		}
		void setFuncName(string func)const
		{
			funcname = func;
		}
		string getFuncName()const
		{
			return funcname;
		}
		void setBackFunc(string func)const
		{
			backfunc = func;
		}
		string getBackFunc()const
		{
			return backfunc;
		}
		void countclear()const
		{
			cnt = 0;
		}
		bool IfCheck()const
		{
			return flag;
			bool a = false;
		}
	};
	/*
	存储free函数及属性
	*/
	class  FreeNodeParam
	{
	private:
		//mutable int ArgLocation;
		mutable vector<int> ArgLocation;
		mutable bool flag;
	public:
		FreeNodeParam()
		{
			flag = false;
		}
		bool IsSetNull()const
		{
			return flag;
		}
		void setNull()const
		{
			flag = true;
		}
		void SetArgLocation(int param)const
		{
			ArgLocation.push_back(param);
		}
		vector<int> getArgLocation()const
		{
			return ArgLocation;
		}

	};
	class FreeRefChecker : public Checker <
		check::PreStmt<Expr>,
		check::ASTDecl<FunctionDecl>,
		check::Location,
		check::EndFunction,
		check::Bind>
	{
	public:
		/*
		读入配置文件
		*/
		FreeRefChecker()
		{
			CallBackFunctionRunTime = 0;
			if (!BT_valueerror){ BT_valueerror.reset(new BugType(this, "FreeRefChecker", "Memory Error")); }
			const auto& config = checker_doc::instance();
			auto v = config.checker_config.at("c4.2").functions_list.at("memFreeFuncs");
			for (auto& elem : v)
			{
				FreeNodeParam inode;
				if (atoi(elem.option_list["isNull"].c_str()) == 1)
					inode.setNull();
				auto vfuncpara = elem.function_parameters;
				for (auto& item : vfuncpara)
					inode.SetArgLocation(item.pos);
				freemap.insert(make_pair(elem.name, inode));
			}
		}
		~FreeRefChecker()
		{
			LOG_INFO << "FreeRefChecker*" << CallBackFunctionRunTime;
		}
		/*
		BinaryOperator的分析函数
		*/
		void AnalysesBO(const BinaryOperator *BO, string opt, string type,
			bool * IsL, bool * IsNull, unsigned int * NAME)const;
		/*
		获取expr中的指针名字
		*/
		void GetArgName(const Expr * E, unsigned int * NAME, bool * IsName)const;
		/*
		具体检查赋值操作，判断是set null 还是新的指针值
		*/
		void checkBind(SVal loc, SVal val, const Stmt *S, CheckerContext &C) const;
		/*
		针对多分支的情况，当一个分支结束时，清空一些map
		*/
		void checkEndFunction(CheckerContext &Ctx) const;
		/*
		checkLocation的辅助函数
		获取checkLocation中的变量名
		*/
		void testLocation(unsigned int *declname, int *flag1, const  Stmt *S)const;

		/*
		检测哪些是正确free,哪些不正确
		*/
		void FindAfterFreeErr(string grandfather, int * countreturn, unsigned int *declname, int * flag, const Stmt *S)const;
		/*
		检查1：是否是free操作
		检查2:free操作之后是否赋新值
		检查3：是否有double free 的情况
		*/
		void checkPreStmt(const Expr *E, CheckerContext &C) const;
		/*
		预先变量代码的ast树，找到free之后紧跟return的情况记录下来
		*/
		void checkASTDecl(const FunctionDecl *FD, AnalysisManager& mgr, BugReporter &BR) const;
		/*
		checkASTDecl的辅助函数
		*/
		void testPostStmt(int *countreturn, unsigned int * PARAMNAME, const Stmt* S)const;
		/*
		double free 的辅助函数
		*/
		void CreatFreeFunc(const Stmt* S, bool * FLAG, vector<pair<unsigned int, int>> * PARAM, map<unsigned int, int>*  parammap, int * ISNULL, string grandfather, string grandgrand, string *bakcstr)const;
		/*
		报错：free之后没有赋予新值:定位报错
		*/
		void ReporterrValue(CheckerContext &C)const;
		void ReportErrFree(CheckerContext &C)const;

		/*
		报错 ：free之后再使用
		*/
		void ReporterrValue2(CheckerContext &C)const;
		/*
		报错：double free操作
		*/
		void ReporterrValue3(CheckerContext &C)const;
		/*
		获取背景函数
		*/
		string getBackFunc(CheckerContext &C)const;

		/*
		具体检查free之后再使用的情况
		*/
		void checkLocation(SVal l, bool isLoad, const Stmt *S, CheckerContext &C) const;//yes
	private:
		mutable std::unique_ptr<BugType> BT_valueerror;		//报错指针
		mutable map<int, ExplodedNode*> CctMap;			//存储free的位置信息
		mutable map<unsigned int, CheckFreeNode> checkfreemap;
		mutable CheckNode checknode;						//是否检查的开关变量
		mutable CheckNode checknode1;						//是否检查的开关变量
		mutable map<unsigned int, int> ptrmap;				// 存放free但没有赋新值的情况
		mutable map<unsigned int, int> NicePtrMap;			//value 2 def nice,检查特出的free后直接return 的情况
		mutable map<string, FreeNodeParam> freemap;			//存放从配置文件读进来的free函数
		mutable map<unsigned int, int> afterfreemap;		//检查after free use 情况
		mutable map<unsigned int, int> afterfreemap0;		//检查after free use 情况
		mutable map<unsigned int, int> doublefreemap;		//检查两次free的情况,1:free 1 次 2：free 2 次 3：free1次后set新值
		mutable map<unsigned int, int> doublefreemap0;		//检查两次free的情况,1:free 1 次 2：free 2 次 3：free1次后set新值
		mutable unsigned long CallBackFunctionRunTime;
	};
} // end anonymous namespace
REGISTER_MAP_WITH_PROGRAMSTATE(FunNameMap, FuncString, FuncString)
void FreeRefChecker::AnalysesBO(const BinaryOperator *BO, string opt, string type,
bool * IsL, bool * IsNull, unsigned int * NAME)const
{
	if (BO && (BO->getOpcodeStr() == opt))
	{
		//左值
		const Expr * E = BO->getLHS();
		if (E)
		{
			const DeclRefExpr * DRE = dyn_cast<DeclRefExpr >(E);
			if (DRE)
			{
				const  ValueDecl *   VDopt = DRE->getDecl();
				if (VDopt)
				{
					*NAME = VDopt->getLocStart().getRawEncoding();
					*IsL = true;
				}
			}
		}
		//右值
		const Expr * EXPR = BO->getRHS();
		if (EXPR)
		{
			const ImplicitCastExpr* ICE = dyn_cast<ImplicitCastExpr>(EXPR);
			if (ICE && (ICE->getCastKindName() == type))				//		"NullToPointer"
				*IsNull = true;
		}
	}
}
void FreeRefChecker::GetArgName(const Expr * EXPR, unsigned int * NAME, bool * IsName)const
{
	if (EXPR)
	{
		const   ImplicitCastExpr  *ICE = dyn_cast< ImplicitCastExpr >(EXPR);
		if (ICE)
		{
			const Expr * E = ICE->IgnoreImpCasts();
			if (E)
			{
				const DeclRefExpr * DRE = dyn_cast<DeclRefExpr >(E);
				if (DRE)
				{
					const  ValueDecl *   VD = DRE->getDecl();
					if (VD)
					{
						*NAME = VD->getLocStart().getRawEncoding();
						*IsName = true;
					}
				}
			}
		}
	}
}
void FreeRefChecker::checkBind(SVal loc, SVal val, const Stmt *S, CheckerContext &C)const
{
	// 用于计时
	int startTime = Timestamp::now();

	string backfunc = getBackFunc(C);
	/*
	BO是否为空在AnalysesBO函数里做了判断
	*/
	bool bo_flag = BinaryOperator::classof(S);
	if (!bo_flag)
		return;
	const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
	bool IsL = false;
	bool IsNull = false;
	unsigned int NAME = 0;
	AnalysesBO(BO, "=", "NullToPointer", &IsL, &IsNull, &NAME);
	if (IsL)
	{
		if (!afterfreemap.count(NAME))
			return;
	}
	if (!IsNull)
	{
		afterfreemap[NAME] = 1;
	}

	// 用于计时
	int endTime = Timestamp::now();
	CallBackFunctionRunTime = CallBackFunctionRunTime + endTime - startTime;
}
void FreeRefChecker::checkEndFunction(CheckerContext &Ctx) const
{
	// 用于计时
	int startTime = Timestamp::now();

	string backfunc = getBackFunc(Ctx);
	doublefreemap.clear();
	afterfreemap.clear();
	for (auto & elem : doublefreemap0)
	{
		doublefreemap.insert(make_pair(elem.first, elem.second));
	}
	for (auto & elem : afterfreemap0)
	{
		afterfreemap.insert(make_pair(elem.first, elem.second));
	}
	if (checknode1.IfCheck())
	{
		if (checknode1.getcount() > 1)
		{
			ReportErrFree(Ctx);
		}
		checknode1.off();
		checknode1.countclear();
	}

	if (checknode.IfCheck())
	{
		if (checknode.getcount() > 1)
		{
			if (checknode.getBackFunc() != getBackFunc(Ctx))
				return;
			ReporterrValue(Ctx);
			checknode.off();
			checknode.countclear();
		}

	}

	// 用于计时
	int endTime = Timestamp::now();
	CallBackFunctionRunTime = CallBackFunctionRunTime + endTime - startTime;
}
void FreeRefChecker::checkLocation(SVal l, bool isLoad, const Stmt *S, CheckerContext &C) const
{
	// 用于计时
	int startTime = Timestamp::now();

	string backfunc = getBackFunc(C);
	unsigned int   DeclName;
	int  ISNAME = 0;
	testLocation(&DeclName, &ISNAME, S);
	if (afterfreemap.count(DeclName))
	{
		if (afterfreemap[DeclName] == 2)
			afterfreemap[DeclName] = 3;
		else if (afterfreemap[DeclName] == 3)
		{
			afterfreemap[DeclName] = 4;// 避免重复报错
			FuncString str(to_string(DeclName));
			if (C.getState()->get<FunNameMap>(str))
			{
				ReporterrValue2(C);
			}
			return;
		}
	}

	// 用于计时
	int endTime = Timestamp::now();
	CallBackFunctionRunTime = CallBackFunctionRunTime + endTime - startTime;
}
void FreeRefChecker::ReporterrValue(CheckerContext &C)const{
	ProgramStateRef State = C.getState();
	ExplodedNode *ErrNode = C.addTransition(State);
	if (!ErrNode){ return; }
	BugReport *R = new BugReport(*BT_valueerror, "error : after free not set new value ", ErrNode);
	C.emitReport(R);
}
void FreeRefChecker::ReportErrFree(CheckerContext &C)const
{
	ProgramStateRef State = C.getState();
	ExplodedNode *ErrNode = C.addTransition(State);
	if (!ErrNode){ return; }
	//BugReport *R = new BugReport(*BT_valueerror, "error : after free not set new value ", ErrNode);
	BugReport *R = new BugReport(*BT_valueerror, "error : Store a new value in pointers immediately after free() ", ErrNode);
	C.emitReport(R);

}
void FreeRefChecker::ReporterrValue2(CheckerContext &C)const{
	ProgramStateRef State = C.getState();
	ExplodedNode *ErrNode = C.addTransition(State);
	if (!ErrNode){ return; }
	//BugReport *R = new BugReport(*BT_valueerror, "error : can`t use after free ", ErrNode);
	BugReport *R = new BugReport(*BT_valueerror, "error : Do not access freed memory ", ErrNode);
	C.emitReport(R);
}
void FreeRefChecker::ReporterrValue3(CheckerContext &C)const{
	ProgramStateRef State = C.getState();
	ExplodedNode *ErrNode = C.addTransition(State);
	if (!ErrNode){ return; }
	//BugReport *R = new BugReport(*BT_valueerror, "error : may be double free ", ErrNode);
	BugReport *R = new BugReport(*BT_valueerror, "error : Free dynamically allocated memory exactly once ", ErrNode);
	C.emitReport(R);
}
string FreeRefChecker::getBackFunc(CheckerContext &C)const
{
	AnalysisDeclContext * ADC = C.getCurrentAnalysisDeclContext();
	if (!ADC)
		return " ";
	const Decl * decl = ADC->getDecl();
	if (!decl)
		return " ";
	string strDeclName = decl->getDeclKindName();
	if (strDeclName != "Function")
		return " ";
	const FunctionDecl * FD = dyn_cast<FunctionDecl>(decl);
	if (!FD)
		return " ";
	StringRef SR = C.getCalleeName(FD);
	if (SR.empty())
		return " ";
	string cbfuname(SR.data());
	return cbfuname;
}
void FreeRefChecker::testPostStmt(int *countreturn, unsigned int * PARAMNAME, const Stmt* S)const
{
	if (!S)
		return;
	unsigned int name = 0;
	if (!(S->children()))
		return;
	for (Expr::const_child_iterator child = S->child_begin(); child != S->child_end(); child++)
	{
		if ((*countreturn) == 1)
			*countreturn = 2;
		if (CallExpr::classof(*child))
		{
			const CallExpr* CE = dyn_cast<CallExpr>(*child);
			if (!CE)
				return;
			const FunctionDecl * FD = CE->getDirectCallee();
			if (!FD)
				return;
			string FuncName = FD->getNameAsString();
			if (freemap.count(FuncName))
			{
				auto ARGS = freemap[FuncName].getArgLocation();
				for (auto& item : ARGS)
				{
					const Expr* E = CE->getArg(item);
					if (!E)
						continue;
					bool IsName = false;
					GetArgName(E, &name, &IsName);
					if (IsName)
						*countreturn = 1;
				}
			}
		}
		if (ReturnStmt::classof(*child))
		{
			if (*countreturn == 2)
				NicePtrMap.insert(make_pair(name, 2));
		}
		if (*countreturn == 2)
			*countreturn = 0;
	}
}
void FreeRefChecker::CreatFreeFunc(const Stmt* S, bool * FLAG, vector<pair<unsigned int, int>> * PARAM,
	map<unsigned int, int> * parammap, int * ISNULL, string grandfather, string grandgrand, string *backstr)const
{
	if (!S)
		return;
	unsigned int name;
	if (ReturnStmt::classof(S))
	{
		if (*ISNULL == 2)
		{
			*ISNULL = 10;
		}
	}
	if (*ISNULL == 2)
	{
		*ISNULL = -1;
	}
	if (CallExpr::classof(S))
	{
		const CallExpr* CE = dyn_cast<CallExpr>(S);
		if (!CE)
			return;
		const FunctionDecl * FD = CE->getDirectCallee();
		if (!FD)
			return;
		string FuncName = FD->getNameAsString();
		if (FuncName.empty())
			return;
		if (freemap.count(FuncName))
		{
			auto ARGS = freemap[FuncName].getArgLocation();
			for (auto& item : ARGS)
			{

				const Expr* E = CE->getArg(item);
				if (!E)
					return;
				bool IsName = false;
				GetArgName(E, &name, &IsName);
				if (IsName)
				{
					(*PARAM).push_back(make_pair(name, item));
					(*parammap).insert(make_pair(name, item));
					*FLAG = true;
					*ISNULL = 1;
					*backstr = grandgrand;
				}
			}

		}
	}
	if (!(S->children()))
		return;
	for (Expr::const_child_iterator child = S->child_begin(); child != S->child_end(); child++)
	{
		if ((*ISNULL) == 1)
			*ISNULL = 2;
		CreatFreeFunc(*child, FLAG, PARAM, parammap, ISNULL, S->getStmtClassName(), grandfather, backstr);
	}
}
void FreeRefChecker::checkASTDecl(const FunctionDecl *FD, AnalysisManager &mgr, BugReporter &BR) const
{

	// 用于计时
	int startTime = Timestamp::now();

	int cnt = 0;
	unsigned int cntname = 0;
	int flag = 0;
	string grandfather = "undef";
	FindAfterFreeErr(grandfather, &cnt, &cntname, &flag, FD->getBody());
	if (checkfreemap.count(cntname) && (cnt == 1))
	{
		CheckFreeNode node = checkfreemap[cntname];
		if (
			(node.getGrandFather() == "ForStmt") ||
			(node.getGrandFather() == "WhileStmt") ||
			(node.getGrandFather() == "DoStmt")
			)
		{
		}
		else
		{
			checkfreemap.erase(cntname);
		}
	}
	int countreturn = 0;
	unsigned int PARAMNAME = 0;
	testPostStmt(&countreturn, &PARAMNAME, FD->getBody());
	if (countreturn == 1)
		NicePtrMap.insert(make_pair(PARAMNAME, 2));
	/*
	bool FLAG = false;
	vector<pair<unsigned int, int>> PARAM;
	map<unsigned int, int> parammap;
	int ISNULL = 0;
	string strfather("undef");
	string strgrand;
	CreatFreeFunc(FD->getBody(), &FLAG, &PARAM, &parammap, &ISNULL, strfather, strfather, &strgrand);
	while (FLAG && strgrand == "undef")
	{

		string namef = FD->getNameAsString();
		size_t num = FD->getNumParams();
		FreeNodeParam inode;
		bool ISFREEFUNC = false;
		for (size_t i = 0; i < num; i++)
		{
			const ParmVarDecl * PVD = FD->getParamDecl(i);
			if (!PVD)
				continue;
			unsigned int VDLoc = PVD->getLocStart().getRawEncoding();
			string VDName = PVD->getNameAsString();
			if (parammap.count(VDLoc))
			{
				ISFREEFUNC = true;
				inode.SetArgLocation(i);
			}
		}
		if (ISFREEFUNC)
			freemap.insert(make_pair(namef, inode));
		FLAG = false;
	}
	*/

	// 用于计时
	int endTime = Timestamp::now();
	CallBackFunctionRunTime = CallBackFunctionRunTime + endTime - startTime;
}
void FreeRefChecker::FindAfterFreeErr(string grandfather, int * countreturn, unsigned int * declname, int * flag, const Stmt *S)const
{
	if (!S)
		return;
	if (*countreturn == 1)
	{
		if (BinaryOperator::classof(S))
		{
			const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
			bool IsL = false;
			bool IsNull = false;
			unsigned int NAME = 0;
			AnalysesBO(BO, "=", "NullToPointer", &IsL, &IsNull, &NAME);
			CheckFreeNode node;
			if (IsL)
			{
				node.setIsL();
				if (*declname == NAME)
				{
					node.setIsRightName();
					if (IsNull)
					{
						node.setIsNull();
					}
				}
			}
			if (checkfreemap.count(*declname))
			{
				node.setGrandFather(checkfreemap[*declname].getGrandFather());
				checkfreemap[*declname] = node;
			}
			else
			{
				checkfreemap.insert(make_pair(*declname, node));
			}
		}
		*countreturn = 0;
		*declname = 0;
	}
	if (!(S->children()))
	{
		return;
	}
	for (Expr::const_child_iterator child = S->child_begin(); child != S->child_end(); child++)
	{
		if (!(*child))
			continue;
		if (CallExpr::classof(*child))
		{
			const CallExpr* CE = dyn_cast<CallExpr>(*child);
			if (!CE)
				continue;
			const FunctionDecl * FD = CE->getDirectCallee();
			if (!FD)
				continue;
			string FuncName = FD->getNameAsString();
			if (FuncName.empty())
				continue;
			if (FuncName == "free")
			{
				const Expr* E = CE->getArg(0);
				if (!E)
					continue;
				bool IsName = false;
				unsigned int NAME = 0;
				GetArgName(E, declname, &IsName);
				if (IsName)
				{
					CheckFreeNode node;
					node.setGrandFather(grandfather);
					checkfreemap.insert(make_pair(*declname, node));
					*countreturn = 1;
					continue;
				}
			}
		}
		if (*countreturn == 1)
		{
			if (!(*child))
				continue;
			if (BinaryOperator::classof(*child))
			{
				const BinaryOperator *BO = dyn_cast<BinaryOperator>(*child);
				bool IsL = false;
				bool IsNull = false;
				unsigned int NAME = 0;
				AnalysesBO(BO, "=", "NullToPointer", &IsL, &IsNull, &NAME);
				CheckFreeNode node;
				if (IsL)
				{
					node.setIsL();
					if (*declname == NAME)
					{
						node.setIsRightName();
						if (IsNull)
						{
							node.setIsNull();
						}
					}
				}
				if (checkfreemap.count(*declname))
				{
					node.setGrandFather(checkfreemap[*declname].getGrandFather());
					checkfreemap[*declname] = node;
				}
				else
				{
					checkfreemap.insert(make_pair(*declname, node));
				}
				*countreturn = 0;
				*declname = 0;
				continue;
			}
			*countreturn = 0;
			*declname = 0;
		}

		FindAfterFreeErr(S->getStmtClassName(), countreturn, declname, flag, (*child));
	}
}
void FreeRefChecker::testLocation(unsigned int *declname, int * flag1, const Stmt * S)const
{
	if (!S)
		return;
	if (DeclRefExpr::classof(S))
	{
		const  DeclRefExpr * declRefExpr = dyn_cast<DeclRefExpr>(S);
		if (!declRefExpr)
			return;
		const  ValueDecl *   valueDecl = declRefExpr->getDecl();
		if (!valueDecl)
			return;
		*declname = valueDecl->getLocStart().getRawEncoding();
		*flag1 = 1;
	}
	if (*flag1 == 1)
		return;
	if (!(S->children()))
		return;
	for (Expr::const_child_iterator child = S->child_begin(); child != S->child_end(); child++){
		testLocation(declname, flag1, (*child));
	}
}
void FreeRefChecker::checkPreStmt(const Expr *E, CheckerContext &C) const
{
	// 用于计时
	int startTime = Timestamp::now();

	ProgramStateRef state = C.getState();
	string backfunc = getBackFunc(C);
	if (checknode.IfCheck())
	{
		std::string FUNCNAME;
		std::vector<int> ARGS;
		std::vector<unsigned int> PARAMS;
		const CallExpr *CE = dyn_cast<CallExpr >(E);
		if (CE)
		{
			const FunctionDecl * FD = CE->getDirectCallee();
			if (FD)
			{
				FUNCNAME = FD->getNameAsString();
				if (
					(freemap.count(FUNCNAME)) &&
					(FUNCNAME != "free")
					)
				{
					ARGS = freemap[FUNCNAME].getArgLocation();
					for (auto& item : ARGS)
					{
						const Expr* EXPR = CE->getArg(item);
						if (!EXPR)
							continue;
						bool IsName = false;
						unsigned int NAME = 0;
						GetArgName(EXPR, &NAME, &IsName);
						if (IsName)
						{
							PARAMS.push_back(NAME);
							if (!afterfreemap.count(NAME))
							{
								afterfreemap.insert(make_pair(NAME, 1));
								afterfreemap0.insert(make_pair(NAME, 1));
							}
							if (doublefreemap.count(NAME))
							{
								ReporterrValue3(C);
								doublefreemap.erase(NAME);
							}
							else
							{
								doublefreemap.insert(make_pair(NAME, 1));
								doublefreemap0.insert(make_pair(NAME, 1));
							}
						}
					} //for (auto& item : ARGS)
				}
			}
		}
		if (checknode.getBackFunc() == backfunc)
		{
			bool bo_flag = BinaryOperator::classof(E);
			if (!bo_flag && (checknode.getcount() <= 3))
			{
				if (checknode.getcount() == 3)
					afterfreemap[checknode.getname()] = 2;
				checknode.setcount();
			}
			else
			{
				bool IsL = false;
				bool IsNUll = false;
				unsigned int namezz = -100;
				if (bo_flag)
				{
					const BinaryOperator *BO = dyn_cast<BinaryOperator>(E);	// 判断是不是做的free操作后的赋值操作
					AnalysesBO(BO, "=", "NullToPointer", &IsL, &IsNUll, &namezz);
				}
				if (IsL)
				{
					if (ptrmap.count(namezz))
					{
						checknode.off();
						checknode.countclear();
						ptrmap.erase(namezz);
						if (IsNUll)
							afterfreemap[namezz] = 2;
						else
							afterfreemap[namezz] = 1;
					}
					else
					{
						ReporterrValue(C);
						checknode.off();
						checknode.countclear();
					}
				}
				ReporterrValue(C);
				checknode.off();
				checknode.countclear();
			}
		}

	}
	else
	{
		const CallExpr *CE = dyn_cast<CallExpr >(E);
		std::string FUNCNAME;
		std::vector<int> ARGS;
		std::vector<unsigned int> PARAMS;
		if (CE)
		{
			const FunctionDecl * FD = CE->getDirectCallee();
			if (FD)
			{
				FUNCNAME = FD->getNameAsString();
				if (
					(freemap.count(FUNCNAME)) &&
					(FUNCNAME != "free")
					)
				{
					ARGS = freemap[FUNCNAME].getArgLocation();
					for (auto& item : ARGS)
					{
						const Expr* EXPR = CE->getArg(item);
						if (!EXPR)
							continue;
						bool IsName = false;
						unsigned int NAME = 0;
						GetArgName(EXPR, &NAME, &IsName);
						if (IsName)
						{
							PARAMS.push_back(NAME);

							if (!afterfreemap.count(NAME))
							{
								afterfreemap.insert(make_pair(NAME, 1));
								afterfreemap0.insert(make_pair(NAME, 1));
							}
							if (doublefreemap.count(NAME))
							{
								ReporterrValue3(C);
								doublefreemap.erase(NAME);
							}
							else
							{
								doublefreemap.insert(make_pair(NAME, 1));
								doublefreemap0.insert(make_pair(NAME, 1));
							}
							if (NicePtrMap.count(NAME))
							{
								continue;
							}
							if (!freemap[FUNCNAME].IsSetNull())
							{
								checknode.on();
								checknode.setname(NAME);
								checknode.setFuncName(FUNCNAME);
								checknode.setBackFunc(backfunc);
								ptrmap.insert(make_pair(NAME, 1));
							}
						}
					} //for (auto& item : ARGS)
				}//if (freemap.count(namef))
			}//if(f)
		}//if (ce)
	}
	const CallExpr *CE = dyn_cast<CallExpr >(E);
	std::string FUNCNAME;
	if (CE)
	{
		const FunctionDecl * FD = CE->getDirectCallee();
		if (FD)
		{
			FUNCNAME = FD->getNameAsString();
			if (FUNCNAME == "free")
			{
				const Expr* EXPR = CE->getArg(0);
				if (!EXPR)
					return;
				bool IsName = false;
				unsigned int NAME = 0;
				GetArgName(EXPR, &NAME, &IsName);
				if (IsName)
				{
					if (NicePtrMap.count(NAME))
					{
						return;
					}
					if (!afterfreemap.count(NAME))
					{
						afterfreemap.insert(make_pair(NAME, 1));
					}
					if (doublefreemap.count(NAME))
					{
						FuncString str(to_string(NAME));
						if (state->get<FunNameMap>(str))
						{
							ReporterrValue3(C);
						}
						doublefreemap.erase(NAME);
					}
					else
					{
						doublefreemap.insert(make_pair(NAME, 1));
					}
					FuncString FunStr_L(to_string(NAME));
					if (!state->get<FunNameMap>(FunStr_L))
					{
						FuncString FunStr_R("1");
						state = state->set<FunNameMap>(FunStr_L, FunStr_R);
						C.addTransition(state);
					}
					if (!freemap[FUNCNAME].IsSetNull())
					{
						if (checkfreemap.count(NAME))
						{
							CheckFreeNode node = checkfreemap[NAME];
							if (node.getIsL())
							{
								if (node.getIsRightName())
								{
									if (node.getIsNull())
										afterfreemap[NAME] = 2;
									else
										afterfreemap[NAME] = 1;

									return;
								}
							}
							ReportErrFree(C);
							afterfreemap[NAME] = 2;
						}
					}
				}
			}//if (freemap.count(namef))
		}//if(f)
	}//if (ce)

	// 用于计时
	int endTime = Timestamp::now();
	CallBackFunctionRunTime = CallBackFunctionRunTime + endTime - startTime;
}
void ento::registerFreeRefChecker(CheckerManager &mgr) {
	mgr.registerChecker<FreeRefChecker>();
}
