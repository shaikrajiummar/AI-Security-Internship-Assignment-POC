"""
ASI05 Mitigation: CodeSandbox
Defense against Unexpected Code Execution.
Techniques:
1. Static AST (Abstract Syntax Tree) Analysis before execution
2. Blacklisting dangerous modules (os, sys, subprocess, shutil, socket)
3. Blacklisting dangerous functions (__import__, eval, exec, open)
"""
import ast
from typing import Tuple

class CodeSandbox(ast.NodeVisitor):
    FORBIDDEN_MODULES = {"os", "sys", "subprocess", "shutil", "socket", "pty", "commands", "ctypes"}
    FORBIDDEN_CALLS = {"eval", "exec", "__import__", "compile", "breakpoint", "getattr"}

    def __init__(self):
        self.violations = []

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in self.FORBIDDEN_MODULES:
                self.violations.append(f"Import of forbidden module '{alias.name}'")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module in self.FORBIDDEN_MODULES:
            self.violations.append(f"Import from forbidden module '{node.module}'")
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check direct function call names
        if isinstance(node.func, ast.Name):
            if node.func.id in self.FORBIDDEN_CALLS:
                self.violations.append(f"Call to forbidden built-in '{node.func.id}()'")
        # Check attribute calls (e.g., os.system)
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in ["system", "popen", "spawn", "rmtree", "unlink", "remove"]:
                self.violations.append(f"Call to forbidden method '{node.func.attr}()'")
        self.generic_visit(node)

    def inspect_ast(self, code_str: str) -> Tuple[bool, str]:
        """
        Parses and inspects code string for security violations.
        """
        try:
            tree = ast.parse(code_str)
            self.violations = []
            self.visit(tree)
            if self.violations:
                return False, "; ".join(self.violations)
            return True, "Code AST verified safe."
        except SyntaxError as e:
            return False, f"Syntax Error: {e}"
