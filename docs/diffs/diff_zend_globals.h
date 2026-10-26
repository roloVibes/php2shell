--- php-8.5.11/Zend/zend_globals.h	2026-09-22 08:32:06
+++ php-8.5.12/Zend/zend_globals.h	2026-10-19 12:02:46
@@ -27,6 +27,7 @@
 
 #include "zend_globals_macros.h"
 
+#include "zend_alloc.h"
 #include "zend_atomic.h"
 #include "zend_stack.h"
 #include "zend_ptr_stack.h"
@@ -134,6 +135,7 @@
 	bool multibyte;
 	bool detect_unicode;
 	bool encoding_declared;
+	bool interned_strings_fallible;
 
 	zend_ast *ast;
 	zend_arena *ast_arena;
@@ -320,6 +322,8 @@
 	zend_strtod_state strtod_state;
 
 	void *reserved[ZEND_MAX_RESERVED_RESOURCES];
+
+	zend_oom_info delayed_oom;
 };
 
 #define EG_FLAGS_INITIAL				(0)
