/* Python interface to types.

   Copyright (C) 2008-2015 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "value.h"
#include "python-internal.h"
#include "charset.h"
#include "gdbtypes.h"
#include "cp-support.h"
#include "demangle.h"
#include "language.h"
#include "vec.h"
#include "expression.h"
#include "typeprint.h"

typedef struct pyexp_expression_object
{
  PyObject_HEAD
  struct expression *type;
  const char *str;

  int nelems;
} expression_object;

typedef struct pyexp_opcode_object
{
  PyObject_HEAD
  struct expression *type;
  int index;
  int limit;

  PyObject *dict;
} opcode_object;

extern PyTypeObject expression_object_type
    CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF ("expression_object");

extern PyTypeObject opcode_object_type
    CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF ("opcode_object");

/* A type iterator object.  */
typedef struct {
  PyObject_HEAD
  /* The current field index.  */
  int index;
  int limit;
  /* Pointer back to the original source type object.  */
  struct pyexp_expression_object *source;
} exppy_iterator_object;

extern PyTypeObject expression_iterator_object_type
    CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF ("exppy_iterator_object");

/* This is used to initialize various gdb.OP_ constants.  */
struct pyexp_code
{
  /* The code.  */
  enum exp_opcode code;
  /* The name.  */
  const char *name;
};

#define OP(X) { X, #X },

static struct pyexp_code pyexp_codes[] =
{
#include "std-operator.def"
  { 0, NULL }
};



static PyObject *
exppy_evaluate_type (PyObject *self, PyObject *args)
{
  struct expression *expression = ((opcode_object *) self)->type;
  struct value *val = evaluate_type(expression);
  struct type *type = value_type(val);
  PyObject *result;

  result = type_to_type_object (type);

  return result;
}

static PyObject *
opcodepy_get_code (PyObject *self, void *closure)
{
  struct expression *expression = ((opcode_object *) self)->type;
  int index = ((opcode_object *) self)->index;

  return PyInt_FromLong (expression->elts[index].opcode);
}

static PyObject *
exppy_make_iter (PyObject *self, int elt, int limit)
{
  exppy_iterator_object *typy_iter_obj;

  typy_iter_obj = PyObject_New (exppy_iterator_object,
				&expression_iterator_object_type);
  if (typy_iter_obj == NULL)
      return NULL;

  typy_iter_obj->index = elt;
  typy_iter_obj->limit = limit;
  Py_INCREF (self);
  typy_iter_obj->source = (expression_object *) self;

  return (PyObject *) typy_iter_obj;
}

static PyObject *
opcodepy_get_children (PyObject *self, PyObject *args)
{
  struct expression *exp = ((opcode_object *) self)->type;
  int elt = ((opcode_object *) self)->index;
  int limit = ((opcode_object *) self)->limit;
  int opcode = exp->elts[elt++].opcode;

  int new_index = elt;
  int new_limit = limit;
  PyObject *result, *iter;

  switch (opcode)
    {
    case TERNOP_COND:
    case TERNOP_SLICE:
    case BINOP_ADD:
    case BINOP_SUB:
    case BINOP_MUL:
    case BINOP_DIV:
    case BINOP_REM:
    case BINOP_MOD:
    case BINOP_LSH:
    case BINOP_RSH:
    case BINOP_LOGICAL_AND:
    case BINOP_LOGICAL_OR:
    case BINOP_BITWISE_AND:
    case BINOP_BITWISE_IOR:
    case BINOP_BITWISE_XOR:
    case BINOP_EQUAL:
    case BINOP_NOTEQUAL:
    case BINOP_LESS:
    case BINOP_GTR:
    case BINOP_LEQ:
    case BINOP_GEQ:
    case BINOP_REPEAT:
    case BINOP_ASSIGN:
    case BINOP_COMMA:
    case BINOP_SUBSCRIPT:
    case BINOP_EXP:
    case BINOP_MIN:
    case BINOP_MAX:
    case BINOP_INTDIV:
    case BINOP_ASSIGN_MODIFY:
    case BINOP_VAL:
    case BINOP_CONCAT:
    case BINOP_END:
    case STRUCTOP_MEMBER:
    case STRUCTOP_MPTR:
    case UNOP_NEG:
    case UNOP_LOGICAL_NOT:
    case UNOP_COMPLEMENT:
    case UNOP_IND:
    case UNOP_ADDR:
    case UNOP_PREINCREMENT:
    case UNOP_POSTINCREMENT:
    case UNOP_PREDECREMENT:
    case UNOP_POSTDECREMENT:
    case UNOP_SIZEOF:
    case UNOP_PLUS:
    case UNOP_CAP:
    case UNOP_CHR:
    case UNOP_ORD:
    case UNOP_ABS:
    case UNOP_FLOAT:
    case UNOP_HIGH:
    case UNOP_MAX:
    case UNOP_MIN:
    case UNOP_ODD:
    case UNOP_TRUNC:
      break;
    case OP_DOUBLE:
    case OP_LONG:
    case OP_VAR_VALUE:
      new_index = elt + 3;
      new_limit = elt + 3;
      break;

    case OP_LAST:
    case OP_VAR_ENTRY_VALUE:
    case OP_INTERNALVAR:
    case TYPE_INSTANCE:
      new_index = elt + 2;
      new_limit = elt + 2;
      break;

    case OP_STRING:
    case OP_REGISTER:
    case STRUCTOP_STRUCT:
    case STRUCTOP_PTR:
      new_index = elt + 3 + BYTES_TO_EXP_ELEM (exp->elts[elt].longconst + 1);
      new_limit = new_index;
      break;

    case OP_FUNCALL:
      new_index = elt + 2;
      break;
    case OP_ARRAY:
      new_index = elt + 3;
      break;
    case UNOP_DYNAMIC_CAST:
    case UNOP_REINTERPRET_CAST:
    case UNOP_CAST_TYPE:
    case UNOP_MEMVAL_TYPE:
      break;
    case UNOP_MEMVAL:
    case UNOP_CAST:
      new_index = elt + 2;
      break;
    case UNOP_MEMVAL_TLS:
      new_index = elt + 3;
      break;
    case OP_TYPE:
      new_index = elt + 2;
      break;
    case OP_TYPEOF:
    case OP_DECLTYPE:
      break;
    case OP_TYPEID:
      break;
    case OP_SCOPE:
      new_index = elt + 4 + BYTES_TO_EXP_ELEM (exp->elts[elt+1].longconst + 1);
      new_limit = new_index;
      break;
    default:
    case OP_NULL:
    case MULTI_SUBSCRIPT:
    case OP_F77_UNDETERMINED_ARGLIST:
    case OP_COMPLEX:
    case OP_BOOL:
    case OP_M2_STRING:
    case OP_THIS:
    case OP_NAME:
      break;
    }

  iter = exppy_make_iter (self, new_index, new_limit);
  result = PySequence_List (iter);

  return result;
}

static PyObject *
opcodepy_get_type (PyObject *self, PyObject *args)
{
  struct expression *exp = ((opcode_object *) self)->type;
  int elt = ((opcode_object *) self)->index;
  int limit = ((opcode_object *) self)->limit;
  int opcode = exp->elts[elt++].opcode;

  int new_index = elt;
  int new_limit = limit;
  PyObject *result = NULL;

  switch (opcode)
    {
    case OP_DOUBLE:
    case OP_LONG:
    case UNOP_MEMVAL:
    case UNOP_CAST:
    case OP_TYPE:
    case OP_SCOPE:
      result = type_to_type_object (exp->elts[elt].type);
      break;
    default:
      break;
    }

  if (result == NULL)
    {
      result = Py_None;
      Py_INCREF (result);
    }

  return result;
}

static PyObject *
opcodepy_get_value (PyObject *self, PyObject *args)
{
  struct expression *exp = ((opcode_object *) self)->type;
  int elt = ((opcode_object *) self)->index;
  int limit = ((opcode_object *) self)->limit;
  int opcode = exp->elts[elt++].opcode;

  int new_index = elt;
  int new_limit = limit;
  PyObject *result = NULL;

  switch (opcode)
    {
    case OP_DOUBLE:
      result = PyFloat_FromDouble (exp->elts[elt+1].doubleconst);
      break;
    case OP_LONG:
      result = PyLong_FromLong (exp->elts[elt+1].longconst);
      break;
    case OP_VAR_VALUE:
      new_index = elt + 3;
      new_limit = elt + 3;
      break;

    case OP_LAST:
    case OP_VAR_ENTRY_VALUE:
    case OP_INTERNALVAR:
    case TYPE_INSTANCE:
      break;

    case OP_REGISTER:
    case STRUCTOP_STRUCT:
    case STRUCTOP_PTR:
      result = PyString_FromStringAndSize (&exp->elts[elt+1].string, exp->elts[elt].longconst);
      break;

    case OP_STRING:
      result = PyString_FromStringAndSize (&exp->elts[elt+3].string, exp->elts[elt+2].longconst);
      break;
    case OP_FUNCALL:
      new_index = elt + 2;
      break;
    case OP_ARRAY:
      new_index = elt + 3;
      break;
    case UNOP_DYNAMIC_CAST:
    case UNOP_REINTERPRET_CAST:
    case UNOP_CAST_TYPE:
    case UNOP_MEMVAL_TYPE:
      break;
    case UNOP_MEMVAL:
    case UNOP_CAST:
      new_index = elt + 2;
      break;
    case UNOP_MEMVAL_TLS:
      new_index = elt + 3;
      break;
    case OP_TYPE:
      new_index = elt + 2;
      break;
    case OP_TYPEOF:
    case OP_DECLTYPE:
      break;
    case OP_TYPEID:
      break;
    case OP_SCOPE:
      new_index = elt + 4 + BYTES_TO_EXP_ELEM (exp->elts[elt+1].longconst + 1);
      new_limit = new_index;
      break;
    default:
    case OP_NULL:
    case MULTI_SUBSCRIPT:
    case OP_F77_UNDETERMINED_ARGLIST:
    case OP_COMPLEX:
    case OP_BOOL:
    case OP_M2_STRING:
    case OP_THIS:
    case OP_NAME:
      break;
    }

  if (result == NULL)
    {
      result = Py_None;
      Py_INCREF (result);
    }

  return result;
}

static struct expression *
exppy_parse_expression (const char *expression_name)
{
  struct expression *expression = NULL;
  volatile struct gdb_exception except;

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      expression = parse_expression (expression_name);
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  return expression;
}

static PyObject *
exppy_str (PyObject *self)
{
  return PyString_FromString (((expression_object *) self)->str);
}

static PyObject *
opcodepy_str (PyObject *self)
{
  return PyString_FromString ("");
}

/* Implement the richcompare method.  */

static PyObject *
exppy_richcompare (PyObject *self, PyObject *other, int op)
{
  Py_RETURN_FALSE;
}



/* Return a reference to the type iterator.  */

static PyObject *
exppy_iterator_iter (PyObject *self)
{
  Py_INCREF (self);
  return self;
}

static PyObject *
opcode_new (void)
{
  opcode_object *result = PyObject_New (opcode_object, &opcode_object_type);
  if (result)
    {
      result->dict = PyDict_New ();
      if (!result->dict)
	{
	  Py_DECREF (result);
	  result = NULL;
	}
    }

  return (PyObject *) result;
}

static PyObject *
convert_opcode (struct expression *type, int field, int limit)
{
  PyObject *result = opcode_new ();
  PyObject *arg;

  if (!result)
    return NULL;

  ((opcode_object *)result)->type = type;
  ((opcode_object *)result)->index = field;
  ((opcode_object *)result)->limit = limit;

  arg = expression_to_expression_object (type);
  if (arg == NULL)
    goto fail;
  if (PyObject_SetAttrString (result, "parent_type", arg) < 0)
    goto failarg;
  //Py_DECREF (arg);

  {
    const char *attrstring;

    {
      arg = gdb_py_long_from_longest (type->elts[field].opcode);
      attrstring = "opcode";
    }

    if (!arg)
      goto fail;

    /* At least python-2.4 had the second parameter non-const.  */
    if (PyObject_SetAttrString (result, (char *) attrstring, arg) < 0)
      goto failarg;
    //Py_DECREF (arg);
  }

  return result;

 failarg:
  //Py_DECREF (arg);
 fail:
  //Py_DECREF (result);
  return NULL;
}

static PyObject *
make_opcode (struct expression *type, int i, int limit)
{
  PyObject *item = NULL, *key = NULL, *value = NULL;

  item =  convert_opcode (type, i, limit);

  return item;
}


static int
expression_skip_subexp (struct expression *exp, int elt)
{
  int opcode = exp->elts[elt++].opcode;

  switch (opcode)
    {
    case TERNOP_COND:
    case TERNOP_SLICE:
      elt = expression_skip_subexp (exp, elt);
      /* FALL THROUGH */
    case BINOP_ADD:
    case BINOP_SUB:
    case BINOP_MUL:
    case BINOP_DIV:
    case BINOP_REM:
    case BINOP_MOD:
    case BINOP_LSH:
    case BINOP_RSH:
    case BINOP_LOGICAL_AND:
    case BINOP_LOGICAL_OR:
    case BINOP_BITWISE_AND:
    case BINOP_BITWISE_IOR:
    case BINOP_BITWISE_XOR:
    case BINOP_EQUAL:
    case BINOP_NOTEQUAL:
    case BINOP_LESS:
    case BINOP_GTR:
    case BINOP_LEQ:
    case BINOP_GEQ:
    case BINOP_REPEAT:
    case BINOP_ASSIGN:
    case BINOP_COMMA:
    case BINOP_SUBSCRIPT:
    case BINOP_EXP:
    case BINOP_MIN:
    case BINOP_MAX:
    case BINOP_INTDIV:
    case BINOP_ASSIGN_MODIFY:
    case BINOP_VAL:
    case BINOP_CONCAT:
    case BINOP_END:
    case STRUCTOP_MEMBER:
    case STRUCTOP_MPTR:
      elt = expression_skip_subexp (exp, elt);
      /* FALL THROUGH */
    case UNOP_NEG:
    case UNOP_LOGICAL_NOT:
    case UNOP_COMPLEMENT:
    case UNOP_IND:
    case UNOP_ADDR:
    case UNOP_PREINCREMENT:
    case UNOP_POSTINCREMENT:
    case UNOP_PREDECREMENT:
    case UNOP_POSTDECREMENT:
    case UNOP_SIZEOF:
    case UNOP_PLUS:
    case UNOP_CAP:
    case UNOP_CHR:
    case UNOP_ORD:
    case UNOP_ABS:
    case UNOP_FLOAT:
    case UNOP_HIGH:
    case UNOP_MAX:
    case UNOP_MIN:
    case UNOP_ODD:
    case UNOP_TRUNC:
      elt = expression_skip_subexp (exp, elt);
      break;
    case OP_LONG:
      elt += 3;
      break;
    case OP_DOUBLE:
      elt += 3;
      break;
    case OP_VAR_VALUE:
      elt += 3;
      break;
    case OP_VAR_ENTRY_VALUE:
      elt += 2;
      break;
    case OP_LAST:
      elt += 2;
      break;
    case OP_REGISTER:
      elt += 3 + BYTES_TO_EXP_ELEM (exp->elts[elt].longconst + 1);
      break;
    case OP_INTERNALVAR:
      elt += 2;
      break;
    case OP_FUNCALL:
      {
	int i, nargs;

	nargs = longest_to_int (exp->elts[elt].longconst);

	elt += 2;

	for (i = 1; i <= nargs + 1; i++)
	  elt = expression_skip_subexp (exp, elt);
      }
      break;
    case OP_ARRAY:
      {
	int lower, upper;
	int i;

	lower = longest_to_int (exp->elts[elt].longconst);
	upper = longest_to_int (exp->elts[elt + 1].longconst);

	elt += 3;

	for (i = 1; i <= upper - lower + 1; i++)
	  elt = expression_skip_subexp (exp, elt);
      }
      break;
    case UNOP_DYNAMIC_CAST:
    case UNOP_REINTERPRET_CAST:
    case UNOP_CAST_TYPE:
    case UNOP_MEMVAL_TYPE:
      elt = expression_skip_subexp (exp, elt);
      elt = expression_skip_subexp (exp, elt);
      break;
    case UNOP_MEMVAL:
    case UNOP_CAST:
      elt = expression_skip_subexp (exp, elt + 2);
      break;
    case UNOP_MEMVAL_TLS:
      elt = expression_skip_subexp (exp, elt + 3);
      break;
    case OP_TYPE:
      elt += 2;
      break;
    case OP_TYPEOF:
    case OP_DECLTYPE:
      elt = expression_skip_subexp (exp, elt);
      break;
    case OP_TYPEID:
      elt = expression_skip_subexp (exp, elt);
      break;
    case STRUCTOP_STRUCT:
    case STRUCTOP_PTR:
      {
	char *elem_name;
	int len;

	len = longest_to_int (exp->elts[elt].longconst);
	elem_name = &exp->elts[elt + 1].string;

	elt = expression_skip_subexp (exp, elt + 3 + BYTES_TO_EXP_ELEM (len + 1));
      }
      break;
    case OP_SCOPE:
      {
	char *elem_name;
	int len;

	len = longest_to_int (exp->elts[elt + 1].longconst);
	elem_name = &exp->elts[elt + 2].string;

	elt += 4 + BYTES_TO_EXP_ELEM (len + 1);
      }
      break;
    case TYPE_INSTANCE:
      {
	LONGEST len;

	len = exp->elts[elt++].longconst;
	while (len-- > 0)
	  {
	    elt++;
	  }
	/* Ending LEN and ending TYPE_INSTANCE.  */
	elt += 2;
	elt = expression_skip_subexp (exp, elt);
      }
      break;
    case OP_STRING:
      {
	LONGEST len = exp->elts[elt].longconst;
	LONGEST type = exp->elts[elt + 1].longconst;

	/* Skip length.  */
	elt += 1;

	/* Skip string content. */
	elt += BYTES_TO_EXP_ELEM (len);

	/* Skip length and ending OP_STRING. */
	elt += 2;
      }
      break;
    default:
    case OP_NULL:
    case MULTI_SUBSCRIPT:
    case OP_F77_UNDETERMINED_ARGLIST:
    case OP_COMPLEX:
    case OP_BOOL:
    case OP_M2_STRING:
    case OP_THIS:
    case OP_NAME:
      break;
    }

  return elt;
}

/* Return the next field in the iteration through the list of fields
   of the type.  */

static PyObject *
exppy_iterator_iternext (PyObject *self)
{
  exppy_iterator_object *iter_obj = (exppy_iterator_object *) self;
  struct expression *type = iter_obj->source->type;
  PyObject *result;

  if (iter_obj->index < iter_obj->limit)
    {
      int elt = iter_obj->index;
      elt = expression_skip_subexp (type, elt);

      result = make_opcode (type, iter_obj->index, elt);
      iter_obj->index = elt;
      return result;
    }
  return NULL;
}

static void
set_expression (expression_object *obj, struct expression *type)
{
  obj->type = type;
  obj->str = "";
}

static void
exppy_iterator_dealloc (PyObject *obj)
{
#if 0
  /* XXX */
  expression_object *type = (expression_object *) obj;

  Py_TYPE (type)->tp_free (type);
#endif
}

static void
exppy_dealloc (PyObject *obj)
{
#if 0
  /* XXX */
  expression_object *type = (expression_object *) obj;

  Py_TYPE (type)->tp_free (type);
#endif
}

static void
opcodepy_dealloc (PyObject *obj)
{
#if 0
  /* XXX */
  expression_object *type = (expression_object *) obj;

  Py_TYPE (type)->tp_free (type);
#endif
}

/* Implements boolean evaluation of gdb.Type.  Handle this like other
   Python objects that don't have a meaningful truth value -- all
   values are true.  */

static int
exppy_nonzero (PyObject *self)
{
  return 1;
}

/* Create a new Type referring to TYPE.  */
PyObject *
expression_to_expression_object (struct expression *type)
{
  expression_object *expression_obj;

  expression_obj = PyObject_New (expression_object, &expression_object_type);
  if (expression_obj) {
    set_expression (expression_obj, type);
  }

  return (PyObject *) expression_obj;
}

struct expression *
expression_object_to_expression (PyObject *obj)
{
  if (! PyObject_TypeCheck (obj, &expression_object_type))
    return NULL;
  return ((expression_object *) obj)->type;
}



PyObject *
gdbpy_parse_expression (PyObject *self, PyObject *args, PyObject *kw);

/* Implementation of gdb.lookup_type.  */
PyObject *
gdbpy_parse_expression (PyObject *self, PyObject *args, PyObject *kw)
{
  static char *keywords[] = { "expr", NULL };
  const char *expression_name = NULL;
  struct expression *type = NULL;

  if (! PyArg_ParseTupleAndKeywords (args, kw, "s|O", keywords,
				     &expression_name))
    return NULL;

  type = exppy_parse_expression (expression_name);
  if (! type)
    return NULL;

  return (PyObject *) expression_to_expression_object (type);
}

/* Return a sequence of all fields.  Each field is a gdb.Field object.
   This method is similar to typy_values, except where the supplied
   gdb.Type is an array, in which case it returns a list of one entry
   which is a gdb.Field object for a range (the array bounds).  */

static PyObject *
exppy_get_opcodes (PyObject *self, PyObject *args)
{
  struct expression *type = ((expression_object *) self)->type;
  PyObject *r, *rl;
  PyObject *py_type = self;
  PyObject *result = NULL, *iter = NULL;
  volatile struct gdb_exception except;

  iter = exppy_make_iter (py_type, 0, type->nelts);
  if (iter != NULL)
    {
      result = PySequence_List (iter);
      //Py_DECREF (iter);
    }

  if (result == NULL)
    {
      result = Py_None;
      Py_INCREF (result);
    }

  return result;
}

static PyObject *
exppy_get_address (PyObject *self, PyObject *args)
{
  struct expression *expression = ((expression_object *) self)->type;

  return PyInt_FromLong ((long)expression);
}

static PyObject *
exppy_dump (PyObject *self, PyObject *args)
{
  struct expression *expression = ((expression_object *) self)->type;

  size_t size = sizeof(struct expression) + expression->nelts * sizeof(expression->elts[0]);

  return PyString_FromStringAndSize((const char *)expression, size);
}

int
gdbpy_initialize_expressions (void);

int
gdbpy_initialize_expressions (void)
{
  int i;
  PyObject *array = PyList_New(128);

  if (PyType_Ready (&expression_object_type) < 0)
    return -1;

  if (PyType_Ready (&opcode_object_type) < 0)
    return -1;

  if (PyType_Ready (&expression_iterator_object_type) < 0)
    return -1;

  for (i = 0; pyexp_codes[i].name; ++i)
    {
      if (PyModule_AddIntConstant (gdb_module,
				   /* Cast needed for Python 2.4.  */
				   (char *) pyexp_codes[i].name,
				   pyexp_codes[i].code) < 0)
	return -1;

      if (PyList_SetItem (array, pyexp_codes[i].code, PyString_FromString ((char *) pyexp_codes[i].name)) < 0)
	return -1;
    }

  if (gdb_pymodule_addobject (gdb_module, "opcodes",
			      array) < 0)
    return -1;

  if (gdb_pymodule_addobject (gdb_module, "Expression",
			      (PyObject *) &expression_object_type) < 0)
    return -1;

  if (gdb_pymodule_addobject (gdb_module, "Opcode",
			      (PyObject *) &opcode_object_type) < 0)
    return -1;

  if (gdb_pymodule_addobject (gdb_module, "ExpressionIterator",
			      (PyObject *) &expression_iterator_object_type) < 0)
    return -1;

  return 0;
}



static PyGetSetDef expression_object_getset[] =
{
  { NULL }
};

static PyGetSetDef opcode_object_getset[] =
{
  { "code", opcodepy_get_code, NULL,
    "The code for this opcode.", NULL },
  { NULL }
};

static PyMethodDef expression_object_methods[] =
{
  { "address", exppy_get_address, METH_NOARGS,
    "address () -> long\n\
Return the integer representing the memory address of the expression."},
  { "dump", exppy_dump, METH_NOARGS,
    "dump () -> long\n\
Dump the entirety of the expression object to stdout."},
  { "evaluate_type", exppy_evaluate_type, METH_NOARGS,
    "address () -> Object\n\
Return the integer representing the memory address of the expression."},
  { "opcodes", exppy_get_opcodes, METH_NOARGS,
    "opcodes () -> list\n\
Return a list holding all the opcodes of this expression.\n\
Each opcode is a gdb.Opcode object." },
  { NULL }
};

static PyMethodDef opcode_object_methods[] =
{
  { "children", opcodepy_get_children, METH_NOARGS,
    "address () -> list\n\
Return the integer representing the memory address of the expression."},
  { "value", opcodepy_get_value, METH_NOARGS,
    "address () -> Object\n\
Return the integer representing the memory address of the expression."},
  { "type", opcodepy_get_type, METH_NOARGS,
    "address () -> Object\n\
Return the integer representing the memory address of the expression."},
  { NULL }
};

static PyNumberMethods expression_object_as_number = {
  NULL,			      /* nb_add */
  NULL,			      /* nb_subtract */
  NULL,			      /* nb_multiply */
#ifndef IS_PY3K
  NULL,			      /* nb_divide */
#endif
  NULL,			      /* nb_remainder */
  NULL,			      /* nb_divmod */
  NULL,			      /* nb_power */
  NULL,			      /* nb_negative */
  NULL,			      /* nb_positive */
  NULL,			      /* nb_absolute */
  exppy_nonzero,		      /* nb_nonzero */
  NULL,			      /* nb_invert */
  NULL,			      /* nb_lshift */
  NULL,			      /* nb_rshift */
  NULL,			      /* nb_and */
  NULL,			      /* nb_xor */
  NULL,			      /* nb_or */
#ifdef IS_PY3K
  NULL,			      /* nb_int */
  NULL,			      /* reserved */
#else
  NULL,			      /* nb_coerce */
  NULL,			      /* nb_int */
  NULL,			      /* nb_long */
#endif
  NULL,			      /* nb_float */
#ifndef IS_PY3K
  NULL,			      /* nb_oct */
  NULL			      /* nb_hex */
#endif
};

PyTypeObject expression_iterator_object_type =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.ExpressionIterator",	  /*tp_name*/
  sizeof (exppy_iterator_object), /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  exppy_iterator_dealloc,	  /*tp_dealloc*/
  0,				  /*tp_print*/
  0,				  /*tp_getattr*/
  0,				  /*tp_setattr*/
  0,				  /*tp_compare*/
  0,				  /*tp_repr*/
  0,				  /*tp_as_number*/
  0,				  /*tp_as_sequence*/
  0,				  /*tp_as_mapping*/
  0,				  /*tp_hash */
  0,				  /*tp_call*/
  0,				  /*tp_str*/
  0,				  /*tp_getattro*/
  0,				  /*tp_setattro*/
  0,				  /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,             /*tp_flags*/
  "GDB expression iterator object",	  /* tp_doc */
  0,				  /* tp_traverse */
  0,				  /* tp_clear */
  0,		  /* tp_richcompare */
  0,				  /* tp_weaklistoffset */
  exppy_iterator_iter,					  /* tp_iter */
  exppy_iterator_iternext,				  /* tp_iternext */
  0,	  /* tp_methods */
  0,				  /* tp_members */
  0,	  /* tp_getset */
  0,				  /* tp_base */
  0,				  /* tp_dict */
  0,				  /* tp_descr_get */
  0,				  /* tp_descr_set */
  0,				  /* tp_dictoffset */
  0,				  /* tp_init */
  0,				  /* tp_alloc */
  0,				  /* tp_new */
};
PyTypeObject expression_object_type =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.Expression",		  /*tp_name*/
  sizeof (expression_object),	  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  exppy_dealloc,		  /*tp_dealloc*/
  0,				  /*tp_print*/
  0,				  /*tp_getattr*/
  0,				  /*tp_setattr*/
  0,				  /*tp_compare*/
  0,				  /*tp_repr*/
  0,				  /*tp_as_number*/
  0,				  /*tp_as_sequence*/
  0,				  /*tp_as_mapping*/
  0,				  /*tp_hash */
  0,				  /*tp_call*/
  exppy_str,			  /*tp_str*/
  0,				  /*tp_getattro*/
  0,				  /*tp_setattro*/
  0,				  /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT,             /*tp_flags*/
  "GDB expression object",	  /* tp_doc */
  0,				  /* tp_traverse */
  0,				  /* tp_clear */
  exppy_richcompare,		  /* tp_richcompare */
  0,				  /* tp_weaklistoffset */
  0,				  /* tp_iter */
  0,				  /* tp_iternext */
  expression_object_methods,	  /* tp_methods */
  0,				  /* tp_members */
  expression_object_getset,	  /* tp_getset */
  0,				  /* tp_base */
  0,				  /* tp_dict */
  0,				  /* tp_descr_get */
  0,				  /* tp_descr_set */
  0,				  /* tp_dictoffset */
  0,				  /* tp_init */
  0,				  /* tp_alloc */
  0,				  /* tp_new */
};

PyTypeObject opcode_object_type =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.Opcode",			  /*tp_name*/
  sizeof (opcode_object),	  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  opcodepy_dealloc,		  /*tp_dealloc*/
  0,				  /*tp_print*/
  0,				  /*tp_getattr*/
  0,				  /*tp_setattr*/
  0,				  /*tp_compare*/
  0,				  /*tp_repr*/
  0,				  /*tp_as_number*/
  0,				  /*tp_as_sequence*/
  0,				  /*tp_as_mapping*/
  0,				  /*tp_hash */
  0,				  /*tp_call*/
  opcodepy_str,			  /*tp_str*/
  0,				  /*tp_getattro*/
  0,				  /*tp_setattro*/
  0,				  /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT,             /*tp_flags*/
  "GDB opcode object",		  /* tp_doc */
  0,				  /* tp_traverse */
  0,				  /* tp_clear */
  0,
  0,				  /* tp_weaklistoffset */
  0,				  /* tp_iter */
  0,				  /* tp_iternext */
  opcode_object_methods,	  /* tp_methods */
  0,				  /* tp_members */
  opcode_object_getset,	  /* tp_getset */
  0,				  /* tp_base */
  0,				  /* tp_dict */
  0,				  /* tp_descr_get */
  0,				  /* tp_descr_set */
  offsetof (opcode_object, dict),  /* tp_dictoffset */
  0,				  /* tp_init */
  0,				  /* tp_alloc */
  0,				  /* tp_new */
};
