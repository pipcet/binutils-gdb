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
#include "objfiles.h"
#include "language.h"
#include "vec.h"
#include "expression.h"
#include "typeprint.h"

typedef struct pyexp_expression_object
{
  PyObject_HEAD
  struct expression *type;

  /* If a Type object is associated with an objfile, it is kept on a
     doubly-linked list, rooted in the objfile.  This lets us copy the
     underlying struct expression when the objfile is deleted.  */
  struct pyexp_expression_object *prev;
  struct pyexp_expression_object *next;
} expression_object;

extern PyTypeObject expression_object_type
    CPYCHECKER_EXPRESSION_OBJECT_FOR_TYPEDEF ("expression_object");

/* A Field object.  */
typedef struct pyexp_field_object
{
  PyObject_HEAD

  /* Dictionary holding our attributes.  */
  PyObject *dict;
} field_object;

extern PyTypeObject field_object_type
    CPYCHECKER_EXPRESSION_OBJECT_FOR_TYPEDEF ("field_object");

/* A type iterator object.  */
typedef struct {
  PyObject_HEAD
  /* The current field index.  */
  int field;
  /* What to return.  */
  enum gdbpy_iter_kind kind;
  /* Pointer back to the original source type object.  */
  struct pyexp_expression_object *source;
} exppy_iterator_object;

extern PyTypeObject expression_iterator_object_type
    CPYCHECKER_EXPRESSION_OBJECT_FOR_TYPEDEF ("exppy_iterator_object");

/* This is used to initialize various gdb.EXPRESSION_ constants.  */
struct pyexp_code
{
  /* The code.  */
  enum expression_code code;
  /* The name.  */
  const char *name;
};

/* Forward declarations.  */
static PyObject *exppy_make_iter (PyObject *self, enum gdbpy_iter_kind kind);

#define ENTRY(X) { X, #X }

static struct pyexp_code pyexp_codes[] =
{
  ENTRY (EXPRESSION_CODE_BITSTRING),
  ENTRY (EXPRESSION_CODE_PTR),
  ENTRY (EXPRESSION_CODE_ARRAY),
  ENTRY (EXPRESSION_CODE_STRUCT),
  ENTRY (EXPRESSION_CODE_UNION),
  ENTRY (EXPRESSION_CODE_ENUM),
  ENTRY (EXPRESSION_CODE_FLAGS),
  ENTRY (EXPRESSION_CODE_FUNC),
  ENTRY (EXPRESSION_CODE_INT),
  ENTRY (EXPRESSION_CODE_FLT),
  ENTRY (EXPRESSION_CODE_VOID),
  ENTRY (EXPRESSION_CODE_SET),
  ENTRY (EXPRESSION_CODE_RANGE),
  ENTRY (EXPRESSION_CODE_STRING),
  ENTRY (EXPRESSION_CODE_ERROR),
  ENTRY (EXPRESSION_CODE_METHOD),
  ENTRY (EXPRESSION_CODE_METHODPTR),
  ENTRY (EXPRESSION_CODE_MEMBERPTR),
  ENTRY (EXPRESSION_CODE_REF),
  ENTRY (EXPRESSION_CODE_CHAR),
  ENTRY (EXPRESSION_CODE_BOOL),
  ENTRY (EXPRESSION_CODE_COMPLEX),
  ENTRY (EXPRESSION_CODE_TYPEDEF),
  ENTRY (EXPRESSION_CODE_NAMESPACE),
  ENTRY (EXPRESSION_CODE_DECFLOAT),
  ENTRY (EXPRESSION_CODE_INTERNAL_FUNCTION),
  { EXPRESSION_CODE_UNDEF, NULL }
};



static void
field_dealloc (PyObject *obj)
{
  field_object *f = (field_object *) obj;

  Py_XDECREF (f->dict);
  Py_TYPE (obj)->tp_free (obj);
}

static PyObject *
field_new (void)
{
  field_object *result = PyObject_New (field_object, &field_object_type);

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



/* Return true if OBJ is of type gdb.Field, false otherwise.  */

int
gdbpy_is_field (PyObject *obj)
{
  return PyObject_TypeCheck (obj, &field_object_type);
}

/* Return the code for this type.  */
static PyObject *
exppy_get_code (PyObject *self, void *closure)
{
  struct expression *type = ((expression_object *) self)->type;

  return PyInt_FromLong (EXPRESSION_CODE (type));
}

/* Helper function for exppy_fields which converts a single field to a
   gdb.Field object.  Returns NULL on error.  */

static PyObject *
convert_field (struct expression *type, int field)
{
  PyObject *result = field_new ();
  PyObject *arg;

  if (!result)
    return NULL;

  arg = expression_to_expression_object (type);
  if (arg == NULL)
    goto fail;
  if (PyObject_SetAttrString (result, "parent_type", arg) < 0)
    goto failarg;
  Py_DECREF (arg);

  if (!field_is_static (&EXPRESSION_FIELD (type, field)))
    {
      const char *attrstring;

      if (EXPRESSION_CODE (type) == EXPRESSION_CODE_ENUM)
	{
	  arg = gdb_py_long_from_longest (EXPRESSION_FIELD_ENUMVAL (type, field));
	  attrstring = "enumval";
	}
      else
	{
	  arg = gdb_py_long_from_longest (EXPRESSION_FIELD_BITPOS (type, field));
	  attrstring = "bitpos";
	}

      if (!arg)
	goto fail;

      /* At least python-2.4 had the second parameter non-const.  */
      if (PyObject_SetAttrString (result, (char *) attrstring, arg) < 0)
	goto failarg;
      Py_DECREF (arg);
    }

  arg = NULL;
  if (EXPRESSION_FIELD_NAME (type, field))
    {
      const char *field_name = EXPRESSION_FIELD_NAME (type, field);

      if (field_name[0] != '\0')
	{
	  arg = PyString_FromString (EXPRESSION_FIELD_NAME (type, field));
	  if (arg == NULL)
	    goto fail;
	}
    }
  if (arg == NULL)
    {
      arg = Py_None;
      Py_INCREF (arg);
    }
  if (PyObject_SetAttrString (result, "name", arg) < 0)
    goto failarg;
  Py_DECREF (arg);

  arg = EXPRESSION_FIELD_ARTIFICIAL (type, field) ? Py_True : Py_False;
  Py_INCREF (arg);
  if (PyObject_SetAttrString (result, "artificial", arg) < 0)
    goto failarg;
  Py_DECREF (arg);

  if (EXPRESSION_CODE (type) == EXPRESSION_CODE_STRUCT)
    arg = field < EXPRESSION_N_BASECLASSES (type) ? Py_True : Py_False;
  else
    arg = Py_False;
  Py_INCREF (arg);
  if (PyObject_SetAttrString (result, "is_base_class", arg) < 0)
    goto failarg;
  Py_DECREF (arg);

  arg = PyLong_FromLong (EXPRESSION_FIELD_BITSIZE (type, field));
  if (!arg)
    goto fail;
  if (PyObject_SetAttrString (result, "bitsize", arg) < 0)
    goto failarg;
  Py_DECREF (arg);

  /* A field can have a NULL type in some situations.  */
  if (EXPRESSION_FIELD_TYPE (type, field) == NULL)
    {
      arg = Py_None;
      Py_INCREF (arg);
    }
  else
    arg = expression_to_expression_object (EXPRESSION_FIELD_TYPE (type, field));
  if (!arg)
    goto fail;
  if (PyObject_SetAttrString (result, "type", arg) < 0)
    goto failarg;
  Py_DECREF (arg);

  return result;

 failarg:
  Py_DECREF (arg);
 fail:
  Py_DECREF (result);
  return NULL;
}

/* Helper function to return the name of a field, as a gdb.Field object.
   If the field doesn't have a name, None is returned.  */

static PyObject *
field_name (struct expression *type, int field)
{
  PyObject *result;

  if (EXPRESSION_FIELD_NAME (type, field))
    result = PyString_FromString (EXPRESSION_FIELD_NAME (type, field));
  else
    {
      result = Py_None;
      Py_INCREF (result);
    }
  return result;
}

/* Helper function for Type standard mapping methods.  Returns a
   Python object for field i of the type.  "kind" specifies what to
   return: the name of the field, a gdb.Field object corresponding to
   the field, or a tuple consisting of field name and gdb.Field
   object.  */

static PyObject *
make_fielditem (struct expression *type, int i, enum gdbpy_iter_kind kind)
{
  PyObject *item = NULL, *key = NULL, *value = NULL;

  switch (kind)
    {
    case iter_items:
      key = field_name (type, i);
      if (key == NULL)
	goto fail;
      value = convert_field (type, i);
      if (value == NULL)
	goto fail;
      item = PyTuple_New (2);
      if (item == NULL)
	goto fail;
      PyTuple_SET_ITEM (item, 0, key);
      PyTuple_SET_ITEM (item, 1, value);
      break;
    case iter_keys:
      item = field_name (type, i);
      break;
    case iter_values:
      item =  convert_field (type, i);
      break;
    default:
      gdb_assert_not_reached ("invalid gdbpy_iter_kind");
    }
  return item;

 fail:
  Py_XDECREF (key);
  Py_XDECREF (value);
  Py_XDECREF (item);
  return NULL;
}

/* Return a sequence of all field names, fields, or (name, field) pairs.
   Each field is a gdb.Field object.  */

static PyObject *
exppy_fields_items (PyObject *self, enum gdbpy_iter_kind kind)
{
  PyObject *py_type = self;
  PyObject *result = NULL, *iter = NULL;
  volatile struct gdb_exception except;
  struct expression *type = ((expression_object *) py_type)->type;
  struct expression *checked_type = type;

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      CHECK_TYPEDEF (checked_type);
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  if (checked_type != type)
    py_type = expression_to_expression_object (checked_type);
  iter = exppy_make_iter (py_type, kind);
  if (checked_type != type)
    {
      /* Need to wrap this in braces because Py_DECREF isn't wrapped
	 in a do{}while(0).  */
      Py_DECREF (py_type);
    }
  if (iter != NULL)
    {
      result = PySequence_List (iter);
      Py_DECREF (iter);
    }

  return result;
}

/* Return a sequence of all fields.  Each field is a gdb.Field object.  */

static PyObject *
exppy_values (PyObject *self, PyObject *args)
{
  return exppy_fields_items (self, iter_values);
}

/* Return a sequence of all fields.  Each field is a gdb.Field object.
   This method is similar to exppy_values, except where the supplied
   gdb.Type is an array, in which case it returns a list of one entry
   which is a gdb.Field object for a range (the array bounds).  */

static PyObject *
exppy_fields (PyObject *self, PyObject *args)
{
  struct expression *type = ((expression_object *) self)->type;
  PyObject *r, *rl;

  if (EXPRESSION_CODE (type) != EXPRESSION_CODE_ARRAY)
    return exppy_fields_items (self, iter_values);

  /* Array type.  Handle this as a special case because the common
     machinery wants struct or union or enum types.  Build a list of
     one entry which is the range for the array.  */
  r = convert_field (type, 0);
  if (r == NULL)
    return NULL;

  rl = Py_BuildValue ("[O]", r);
  Py_DECREF (r);

  return rl;
}

/* Return a sequence of all field names.  Each field is a gdb.Field object.  */

static PyObject *
exppy_field_names (PyObject *self, PyObject *args)
{
  return exppy_fields_items (self, iter_keys);
}

/* Return a sequence of all (name, fields) pairs.  Each field is a
   gdb.Field object.  */

static PyObject *
exppy_items (PyObject *self, PyObject *args)
{
  return exppy_fields_items (self, iter_items);
}

/* Return the type's name, or None.  */

static PyObject *
exppy_get_name (PyObject *self, void *closure)
{
  struct expression *type = ((expression_object *) self)->type;

  if (EXPRESSION_NAME (type) == NULL)
    Py_RETURN_NONE;
  return PyString_FromString (EXPRESSION_NAME (type));
}

/* Return the type's tag, or None.  */
static PyObject *
exppy_get_tag (PyObject *self, void *closure)
{
  struct expression *type = ((expression_object *) self)->type;

  if (!EXPRESSION_TAG_NAME (type))
    Py_RETURN_NONE;
  return PyString_FromString (EXPRESSION_TAG_NAME (type));
}

/* Return the type, stripped of typedefs. */
static PyObject *
exppy_strip_typedefs (PyObject *self, PyObject *args)
{
  struct expression *type = ((expression_object *) self)->type;
  volatile struct gdb_exception except;

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      type = check_typedef (type);
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  return expression_to_expression_object (type);
}

/* Strip typedefs and pointers/reference from a type.  Then check that
   it is a struct, union, or enum type.  If not, raise TypeError.  */

static struct expression *
exppy_get_composite (struct expression *type)
{
  volatile struct gdb_exception except;

  for (;;)
    {
      TRY_CATCH (except, RETURN_MASK_ALL)
	{
	  CHECK_TYPEDEF (type);
	}
      GDB_PY_HANDLE_EXCEPTION (except);

      if (EXPRESSION_CODE (type) != EXPRESSION_CODE_PTR
	  && EXPRESSION_CODE (type) != EXPRESSION_CODE_REF)
	break;
      type = EXPRESSION_TARGET_TYPE (type);
    }

  /* If this is not a struct, union, or enum type, raise TypeError
     exception.  */
  if (EXPRESSION_CODE (type) != EXPRESSION_CODE_STRUCT
      && EXPRESSION_CODE (type) != EXPRESSION_CODE_UNION
      && EXPRESSION_CODE (type) != EXPRESSION_CODE_ENUM
      && EXPRESSION_CODE (type) != EXPRESSION_CODE_FUNC)
    {
      PyErr_SetString (PyExc_TypeError,
		       "Type is not a structure, union, enum, or function type.");
      return NULL;
    }

  return type;
}

/* Helper for exppy_array and exppy_vector.  */

static PyObject *
exppy_array_1 (PyObject *self, PyObject *args, int is_vector)
{
  long n1, n2;
  PyObject *n2_obj = NULL;
  struct expression *array = NULL;
  struct expression *type = ((expression_object *) self)->type;
  volatile struct gdb_exception except;

  if (! PyArg_ParseTuple (args, "l|O", &n1, &n2_obj))
    return NULL;

  if (n2_obj)
    {
      if (!PyInt_Check (n2_obj))
	{
	  PyErr_SetString (PyExc_RuntimeError,
			   _("Array bound must be an integer"));
	  return NULL;
	}

      if (! gdb_py_int_as_long (n2_obj, &n2))
	return NULL;
    }
  else
    {
      n2 = n1;
      n1 = 0;
    }

  if (n2 < n1 - 1) /* Note: An empty array has n2 == n1 - 1.  */
    {
      PyErr_SetString (PyExc_ValueError,
		       _("Array length must not be negative"));
      return NULL;
    }

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      array = lookup_array_range_type (type, n1, n2);
      if (is_vector)
	make_vector_type (array);
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  return expression_to_expression_object (array);
}

/* Return an array type.  */

static PyObject *
exppy_array (PyObject *self, PyObject *args)
{
  return exppy_array_1 (self, args, 0);
}

/* Return a vector type.  */

static PyObject *
exppy_vector (PyObject *self, PyObject *args)
{
  return exppy_array_1 (self, args, 1);
}

/* Return a Type object which represents a pointer to SELF.  */
static PyObject *
exppy_pointer (PyObject *self, PyObject *args)
{
  struct expression *type = ((expression_object *) self)->type;
  volatile struct gdb_exception except;

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      type = lookup_pointer_type (type);
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  return expression_to_expression_object (type);
}

/* Return the range of a type represented by SELF.  The return type is
   a tuple.  The first element of the tuple contains the low bound,
   while the second element of the tuple contains the high bound.  */
static PyObject *
exppy_range (PyObject *self, PyObject *args)
{
  struct expression *type = ((expression_object *) self)->type;
  PyObject *result;
  PyObject *low_bound = NULL, *high_bound = NULL;
  /* Initialize these to appease GCC warnings.  */
  LONGEST low = 0, high = 0;

  if (EXPRESSION_CODE (type) != EXPRESSION_CODE_ARRAY
      && EXPRESSION_CODE (type) != EXPRESSION_CODE_STRING
      && EXPRESSION_CODE (type) != EXPRESSION_CODE_RANGE)
    {
      PyErr_SetString (PyExc_RuntimeError,
		       _("This type does not have a range."));
      return NULL;
    }

  switch (EXPRESSION_CODE (type))
    {
    case EXPRESSION_CODE_ARRAY:
    case EXPRESSION_CODE_STRING:
      low = EXPRESSION_LOW_BOUND (EXPRESSION_INDEX_TYPE (type));
      high = EXPRESSION_HIGH_BOUND (EXPRESSION_INDEX_TYPE (type));
      break;
    case EXPRESSION_CODE_RANGE:
      low = EXPRESSION_LOW_BOUND (type);
      high = EXPRESSION_HIGH_BOUND (type);
      break;
    }

  low_bound = PyLong_FromLong (low);
  if (!low_bound)
    goto failarg;

  high_bound = PyLong_FromLong (high);
  if (!high_bound)
    goto failarg;

  result = PyTuple_New (2);
  if (!result)
    goto failarg;

  if (PyTuple_SetItem (result, 0, low_bound) != 0)
    {
      Py_DECREF (result);
      goto failarg;
    }
  if (PyTuple_SetItem (result, 1, high_bound) != 0)
    {
      Py_DECREF (high_bound);
      Py_DECREF (result);
      return NULL;
    }
  return result;

 failarg:
  Py_XDECREF (high_bound);
  Py_XDECREF (low_bound);
  return NULL;
}

/* Return a Type object which represents a reference to SELF.  */
static PyObject *
exppy_reference (PyObject *self, PyObject *args)
{
  struct expression *type = ((expression_object *) self)->type;
  volatile struct gdb_exception except;

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      type = lookup_reference_type (type);
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  return expression_to_expression_object (type);
}

/* Return a Type object which represents the target type of SELF.  */
static PyObject *
exppy_target (PyObject *self, PyObject *args)
{
  struct expression *type = ((expression_object *) self)->type;

  if (!EXPRESSION_TARGET_TYPE (type))
    {
      PyErr_SetString (PyExc_RuntimeError,
		       _("Type does not have a target."));
      return NULL;
    }

  return expression_to_expression_object (EXPRESSION_TARGET_TYPE (type));
}

/* Return a const-qualified type variant.  */
static PyObject *
exppy_const (PyObject *self, PyObject *args)
{
  struct expression *type = ((expression_object *) self)->type;
  volatile struct gdb_exception except;

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      type = make_cv_type (1, 0, type, NULL);
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  return expression_to_expression_object (type);
}

/* Return a volatile-qualified type variant.  */
static PyObject *
exppy_volatile (PyObject *self, PyObject *args)
{
  struct expression *type = ((expression_object *) self)->type;
  volatile struct gdb_exception except;

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      type = make_cv_type (0, 1, type, NULL);
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  return expression_to_expression_object (type);
}

/* Return an unqualified type variant.  */
static PyObject *
exppy_unqualified (PyObject *self, PyObject *args)
{
  struct expression *type = ((expression_object *) self)->type;
  volatile struct gdb_exception except;

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      type = make_cv_type (0, 0, type, NULL);
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  return expression_to_expression_object (type);
}

/* Return the size of the type represented by SELF, in bytes.  */
static PyObject *
exppy_get_sizeof (PyObject *self, void *closure)
{
  struct expression *type = ((expression_object *) self)->type;
  volatile struct gdb_exception except;

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      check_typedef (type);
    }
  /* Ignore exceptions.  */

  return gdb_py_long_from_longest (EXPRESSION_LENGTH (type));
}

static struct expression *
exppy_lookup_typename (const char *expression_name, const struct block *block)
{
  struct expression *type = NULL;
  volatile struct gdb_exception except;

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      if (!strncmp (expression_name, "struct ", 7))
	type = lookup_struct (expression_name + 7, NULL);
      else if (!strncmp (expression_name, "union ", 6))
	type = lookup_union (expression_name + 6, NULL);
      else if (!strncmp (expression_name, "enum ", 5))
	type = lookup_enum (expression_name + 5, NULL);
      else
	type = lookup_typename (python_language, python_gdbarch,
				expression_name, block, 0);
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  return type;
}

static struct expression *
exppy_lookup_type (struct demangle_component *demangled,
		  const struct block *block)
{
  struct expression *type, *rtype = NULL;
  char *expression_name = NULL;
  enum demangle_component_type demangled_type;
  volatile struct gdb_exception except;

  /* Save the type: exppy_lookup_type() may (indirectly) overwrite
     memory pointed by demangled.  */
  demangled_type = demangled->type;

  if (demangled_type == DEMANGLE_COMPONENT_POINTER
      || demangled_type == DEMANGLE_COMPONENT_REFERENCE
      || demangled_type == DEMANGLE_COMPONENT_CONST
      || demangled_type == DEMANGLE_COMPONENT_VOLATILE)
    {
      type = exppy_lookup_type (demangled->u.s_binary.left, block);
      if (! type)
	return NULL;

      TRY_CATCH (except, RETURN_MASK_ALL)
	{
	  /* If the demangled_type matches with one of the types
	     below, run the corresponding function and save the type
	     to return later.  We cannot just return here as we are in
	     an exception handler.  */
	  switch (demangled_type)
	    {
	    case DEMANGLE_COMPONENT_REFERENCE:
	      rtype =  lookup_reference_type (type);
	      break;
	    case DEMANGLE_COMPONENT_POINTER:
	      rtype = lookup_pointer_type (type);
	      break;
	    case DEMANGLE_COMPONENT_CONST:
	      rtype = make_cv_type (1, 0, type, NULL);
	      break;
	    case DEMANGLE_COMPONENT_VOLATILE:
	      rtype = make_cv_type (0, 1, type, NULL);
	      break;
	    }
	}
      GDB_PY_HANDLE_EXCEPTION (except);
    }

  /* If we have a type from the switch statement above, just return
     that.  */
  if (rtype)
    return rtype;

  /* We don't have a type, so lookup the type.  */
  expression_name = cp_comp_to_string (demangled, 10);
  type = exppy_lookup_typename (expression_name, block);
  xfree (expression_name);

  return type;
}

/* This is a helper function for exppy_template_argument that is used
   when the type does not have template symbols attached.  It works by
   parsing the type name.  This happens with compilers, like older
   versions of GCC, that do not emit DW_TAG_template_*.  */

static PyObject *
exppy_legacy_template_argument (struct expression *type, const struct block *block,
			       int argno)
{
  int i;
  struct demangle_component *demangled;
  struct demangle_parse_info *info = NULL;
  const char *err;
  struct expression *argtype;
  struct cleanup *cleanup;
  volatile struct gdb_exception except;

  if (EXPRESSION_NAME (type) == NULL)
    {
      PyErr_SetString (PyExc_RuntimeError, _("Null type name."));
      return NULL;
    }

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      /* Note -- this is not thread-safe.  */
      info = cp_demangled_name_to_comp (EXPRESSION_NAME (type), &err);
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  if (! info)
    {
      PyErr_SetString (PyExc_RuntimeError, err);
      return NULL;
    }
  demangled = info->tree;
  cleanup = make_cleanup_cp_demangled_name_parse_free (info);

  /* Strip off component names.  */
  while (demangled->type == DEMANGLE_COMPONENT_QUAL_NAME
	 || demangled->type == DEMANGLE_COMPONENT_LOCAL_NAME)
    demangled = demangled->u.s_binary.right;

  if (demangled->type != DEMANGLE_COMPONENT_TEMPLATE)
    {
      do_cleanups (cleanup);
      PyErr_SetString (PyExc_RuntimeError, _("Type is not a template."));
      return NULL;
    }

  /* Skip from the template to the arguments.  */
  demangled = demangled->u.s_binary.right;

  for (i = 0; demangled && i < argno; ++i)
    demangled = demangled->u.s_binary.right;

  if (! demangled)
    {
      do_cleanups (cleanup);
      PyErr_Format (PyExc_RuntimeError, _("No argument %d in template."),
		    argno);
      return NULL;
    }

  argtype = exppy_lookup_type (demangled->u.s_binary.left, block);
  do_cleanups (cleanup);
  if (! argtype)
    return NULL;

  return expression_to_expression_object (argtype);
}

static PyObject *
exppy_template_argument (PyObject *self, PyObject *args)
{
  int argno;
  struct expression *type = ((expression_object *) self)->type;
  const struct block *block = NULL;
  PyObject *block_obj = NULL;
  struct symbol *sym;
  struct value *val = NULL;
  volatile struct gdb_exception except;

  if (! PyArg_ParseTuple (args, "i|O", &argno, &block_obj))
    return NULL;

  if (block_obj)
    {
      block = block_object_to_block (block_obj);
      if (! block)
	{
	  PyErr_SetString (PyExc_RuntimeError,
			   _("Second argument must be block."));
	  return NULL;
	}
    }

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      type = check_typedef (type);
      if (EXPRESSION_CODE (type) == EXPRESSION_CODE_REF)
	type = check_typedef (EXPRESSION_TARGET_TYPE (type));
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  /* We might not have DW_TAG_template_*, so try to parse the type's
     name.  This is inefficient if we do not have a template type --
     but that is going to wind up as an error anyhow.  */
  if (! EXPRESSION_N_TEMPLATE_ARGUMENTS (type))
    return exppy_legacy_template_argument (type, block, argno);

  if (argno >= EXPRESSION_N_TEMPLATE_ARGUMENTS (type))
    {
      PyErr_Format (PyExc_RuntimeError, _("No argument %d in template."),
		    argno);
      return NULL;
    }

  sym = EXPRESSION_TEMPLATE_ARGUMENT (type, argno);
  if (SYMBOL_CLASS (sym) == LOC_TYPEDEF)
    return expression_to_expression_object (SYMBOL_TYPE (sym));
  else if (SYMBOL_CLASS (sym) == LOC_OPTIMIZED_OUT)
    {
      PyErr_Format (PyExc_RuntimeError,
		    _("Template argument is optimized out"));
      return NULL;
    }

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      val = value_of_variable (sym, block);
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  return value_to_value_object (val);
}

static PyObject *
exppy_str (PyObject *self)
{
  volatile struct gdb_exception except;
  char *thetype = NULL;
  long length = 0;
  PyObject *result;

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      struct cleanup *old_chain;
      struct ui_file *stb;

      stb = mem_fileopen ();
      old_chain = make_cleanup_ui_file_delete (stb);

      LA_PRINT_TYPE (expression_object_to_type (self), "", stb, -1, 0,
		     &expression_print_raw_options);

      thetype = ui_file_xstrdup (stb, &length);
      do_cleanups (old_chain);
    }
  if (except.reason < 0)
    {
      xfree (thetype);
      GDB_PY_HANDLE_EXCEPTION (except);
    }

  result = PyUnicode_Decode (thetype, length, host_charset (), NULL);
  xfree (thetype);

  return result;
}

/* Implement the richcompare method.  */

static PyObject *
exppy_richcompare (PyObject *self, PyObject *other, int op)
{
  int result = Py_NE;
  struct expression *type1 = expression_object_to_type (self);
  struct expression *type2 = expression_object_to_type (other);
  volatile struct gdb_exception except;

  /* We can only compare ourselves to another Type object, and only
     for equality or inequality.  */
  if (type2 == NULL || (op != Py_EQ && op != Py_NE))
    {
      Py_INCREF (Py_NotImplemented);
      return Py_NotImplemented;
    }

  if (type1 == type2)
    result = Py_EQ;
  else
    {
      TRY_CATCH (except, RETURN_MASK_ALL)
	{
	  result = types_deeply_equal (type1, type2);
	}
      /* If there is a GDB exception, a comparison is not capable
	 (or trusted), so exit.  */
      GDB_PY_HANDLE_EXCEPTION (except);
    }

  if (op == (result ? Py_EQ : Py_NE))
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}



static const struct objfile_data *exppy_objfile_data_key;

static void
save_objfile_types (struct objfile *objfile, void *datum)
{
  expression_object *obj = datum;
  htab_t copied_types;
  struct cleanup *cleanup;

  if (!gdb_python_initialized)
    return;

  /* This prevents another thread from freeing the objects we're
     operating on.  */
  cleanup = ensure_python_env (get_objfile_arch (objfile), current_language);

  copied_types = create_copied_types_hash (objfile);

  while (obj)
    {
      expression_object *next = obj->next;

      htab_empty (copied_types);

      obj->type = copy_expression_recursive (objfile, obj->type, copied_types);

      obj->next = NULL;
      obj->prev = NULL;

      obj = next;
    }

  htab_delete (copied_types);

  do_cleanups (cleanup);
}

static void
set_type (expression_object *obj, struct expression *type)
{
  obj->type = type;
  obj->prev = NULL;
  if (type && EXPRESSION_OBJFILE (type))
    {
      struct objfile *objfile = EXPRESSION_OBJFILE (type);

      obj->next = objfile_data (objfile, exppy_objfile_data_key);
      if (obj->next)
	obj->next->prev = obj;
      set_objfile_data (objfile, exppy_objfile_data_key, obj);
    }
  else
    obj->next = NULL;
}

static void
exppy_dealloc (PyObject *obj)
{
  expression_object *type = (expression_object *) obj;

  if (type->prev)
    type->prev->next = type->next;
  else if (type->type && EXPRESSION_OBJFILE (type->type))
    {
      /* Must reset head of list.  */
      struct objfile *objfile = EXPRESSION_OBJFILE (type->type);

      if (objfile)
	set_objfile_data (objfile, exppy_objfile_data_key, type->next);
    }
  if (type->next)
    type->next->prev = type->prev;

  Py_TYPE (type)->tp_free (type);
}

/* Return number of fields ("length" of the field dictionary).  */

static Py_ssize_t
exppy_length (PyObject *self)
{
  struct expression *type = ((expression_object *) self)->type;

  type = exppy_get_composite (type);
  if (type == NULL)
    return -1;

  return EXPRESSION_NFIELDS (type);
}

/* Implements boolean evaluation of gdb.Type.  Handle this like other
   Python objects that don't have a meaningful truth value -- all
   values are true.  */

static int
exppy_nonzero (PyObject *self)
{
  return 1;
}

/* Return a gdb.Field object for the field named by the argument.  */

static PyObject *
exppy_getitem (PyObject *self, PyObject *key)
{
  struct expression *type = ((expression_object *) self)->type;
  char *field;
  int i;

  field = python_string_to_host_string (key);
  if (field == NULL)
    return NULL;

  /* We want just fields of this type, not of base types, so instead of
     using lookup_struct_elt_type, portions of that function are
     copied here.  */

  type = exppy_get_composite (type);
  if (type == NULL)
    return NULL;

  for (i = 0; i < EXPRESSION_NFIELDS (type); i++)
    {
      const char *t_field_name = EXPRESSION_FIELD_NAME (type, i);

      if (t_field_name && (strcmp_iw (t_field_name, field) == 0))
	{
	  return convert_field (type, i);
	}
    }
  PyErr_SetObject (PyExc_KeyError, key);
  return NULL;
}

/* Implement the "get" method on the type object.  This is the
   same as getitem if the key is present, but returns the supplied
   default value or None if the key is not found.  */

static PyObject *
exppy_get (PyObject *self, PyObject *args)
{
  PyObject *key, *defval = Py_None, *result;

  if (!PyArg_UnpackTuple (args, "get", 1, 2, &key, &defval))
    return NULL;

  result = exppy_getitem (self, key);
  if (result != NULL)
    return result;

  /* exppy_getitem returned error status.  If the exception is
     KeyError, clear the exception status and return the defval
     instead.  Otherwise return the exception unchanged.  */
  if (!PyErr_ExceptionMatches (PyExc_KeyError))
    return NULL;

  PyErr_Clear ();
  Py_INCREF (defval);
  return defval;
}

/* Implement the "has_key" method on the type object.  */

static PyObject *
exppy_has_key (PyObject *self, PyObject *args)
{
  struct expression *type = ((expression_object *) self)->type;
  const char *field;
  int i;

  if (!PyArg_ParseTuple (args, "s", &field))
    return NULL;

  /* We want just fields of this type, not of base types, so instead of
     using lookup_struct_elt_type, portions of that function are
     copied here.  */

  type = exppy_get_composite (type);
  if (type == NULL)
    return NULL;

  for (i = 0; i < EXPRESSION_NFIELDS (type); i++)
    {
      const char *t_field_name = EXPRESSION_FIELD_NAME (type, i);

      if (t_field_name && (strcmp_iw (t_field_name, field) == 0))
	Py_RETURN_TRUE;
    }
  Py_RETURN_FALSE;
}

/* Make an iterator object to iterate over keys, values, or items.  */

static PyObject *
exppy_make_iter (PyObject *self, enum gdbpy_iter_kind kind)
{
  exppy_iterator_object *exppy_iter_obj;

  /* Check that "self" is a structure or union type.  */
  if (exppy_get_composite (((expression_object *) self)->type) == NULL)
    return NULL;

  exppy_iter_obj = PyObject_New (exppy_iterator_object,
				&expression_iterator_object_type);
  if (exppy_iter_obj == NULL)
      return NULL;

  exppy_iter_obj->field = 0;
  exppy_iter_obj->kind = kind;
  Py_INCREF (self);
  exppy_iter_obj->source = (expression_object *) self;

  return (PyObject *) exppy_iter_obj;
}

/* iteritems() method.  */

static PyObject *
exppy_iteritems (PyObject *self, PyObject *args)
{
  return exppy_make_iter (self, iter_items);
}

/* iterkeys() method.  */

static PyObject *
exppy_iterkeys (PyObject *self, PyObject *args)
{
  return exppy_make_iter (self, iter_keys);
}

/* Iterating over the class, same as iterkeys except for the function
   signature.  */

static PyObject *
exppy_iter (PyObject *self)
{
  return exppy_make_iter (self, iter_keys);
}

/* itervalues() method.  */

static PyObject *
exppy_itervalues (PyObject *self, PyObject *args)
{
  return exppy_make_iter (self, iter_values);
}

/* Return a reference to the type iterator.  */

static PyObject *
exppy_iterator_iter (PyObject *self)
{
  Py_INCREF (self);
  return self;
}

/* Return the next field in the iteration through the list of fields
   of the type.  */

static PyObject *
exppy_iterator_iternext (PyObject *self)
{
  exppy_iterator_object *iter_obj = (exppy_iterator_object *) self;
  struct expression *type = iter_obj->source->type;
  PyObject *result;

  if (iter_obj->field < EXPRESSION_NFIELDS (type))
    {
      result = make_fielditem (type, iter_obj->field, iter_obj->kind);
      if (result != NULL)
	iter_obj->field++;
      return result;
    }

  return NULL;
}

static void
exppy_iterator_dealloc (PyObject *obj)
{
  exppy_iterator_object *iter_obj = (exppy_iterator_object *) obj;

  Py_DECREF (iter_obj->source);
}

/* Create a new Type referring to TYPE.  */
PyObject *
expression_to_expression_object (struct expression *type)
{
  expression_object *expression_obj;

  expression_obj = PyObject_New (expression_object, &expression_object_type);
  if (expression_obj)
    set_type (expression_obj, type);

  return (PyObject *) expression_obj;
}

struct expression *
expression_object_to_type (PyObject *obj)
{
  if (! PyObject_TypeCheck (obj, &expression_object_type))
    return NULL;
  return ((expression_object *) obj)->type;
}



/* Implementation of gdb.lookup_type.  */
PyObject *
gdbpy_parse_expression (PyObject *self, PyObject *args, PyObject *kw)
{
  static char *keywords[] = { "name", "block", NULL };
  const char *expression_name = NULL;
  struct expression *type = NULL;
  PyObject *block_obj = NULL;
  const struct block *block = NULL;

  if (! PyArg_ParseTupleAndKeywords (args, kw, "s|O", keywords,
				     &expression_name, &block_obj))
    return NULL;

  if (block_obj)
    {
      block = block_object_to_block (block_obj);
      if (! block)
	{
	  PyErr_SetString (PyExc_RuntimeError,
			   _("'block' argument must be a Block."));
	  return NULL;
	}
    }

  type = exppy_lookup_typename (expression_name, block);
  if (! type)
    return NULL;

  return (PyObject *) expression_to_expression_object (type);
}

int
gdbpy_initialize_types (void)
{
  int i;

  exppy_objfile_data_key
    = register_objfile_data_with_cleanup (save_objfile_types, NULL);

  if (PyExpression_Ready (&expression_object_type) < 0)
    return -1;
  if (PyExpression_Ready (&field_object_type) < 0)
    return -1;
  if (PyExpression_Ready (&expression_iterator_object_type) < 0)
    return -1;

  for (i = 0; pyexp_codes[i].name; ++i)
    {
      if (PyModule_AddIntConstant (gdb_module,
				   /* Cast needed for Python 2.4.  */
				   (char *) pyexp_codes[i].name,
				   pyexp_codes[i].code) < 0)
	return -1;
    }

  if (gdb_pymodule_addobject (gdb_module, "Type",
			      (PyObject *) &expression_object_type) < 0)
    return -1;

  if (gdb_pymodule_addobject (gdb_module, "TypeIterator",
			      (PyObject *) &expression_iterator_object_type) < 0)
    return -1;

  return gdb_pymodule_addobject (gdb_module, "Field",
				 (PyObject *) &field_object_type);
}



static PyGetSetDef expression_object_getset[] =
{
  { "code", exppy_get_code, NULL,
    "The code for this type.", NULL },
  { "name", exppy_get_name, NULL,
    "The name for this type, or None.", NULL },
  { "sizeof", exppy_get_sizeof, NULL,
    "The size of this type, in bytes.", NULL },
  { "tag", exppy_get_tag, NULL,
    "The tag name for this type, or None.", NULL },
  { NULL }
};

static PyMethodDef expression_object_methods[] =
{
  { "array", exppy_array, METH_VARARGS,
    "array ([LOW_BOUND,] HIGH_BOUND) -> Type\n\
Return a type which represents an array of objects of this type.\n\
The bounds of the array are [LOW_BOUND, HIGH_BOUND] inclusive.\n\
If LOW_BOUND is omitted, a value of zero is used." },
  { "vector", exppy_vector, METH_VARARGS,
    "vector ([LOW_BOUND,] HIGH_BOUND) -> Type\n\
Return a type which represents a vector of objects of this type.\n\
The bounds of the array are [LOW_BOUND, HIGH_BOUND] inclusive.\n\
If LOW_BOUND is omitted, a value of zero is used.\n\
Vectors differ from arrays in that if the current language has C-style\n\
arrays, vectors don't decay to a pointer to the first element.\n\
They are first class values." },
   { "__contains__", exppy_has_key, METH_VARARGS,
     "T.__contains__(k) -> True if T has a field named k, else False" },
  { "const", exppy_const, METH_NOARGS,
    "const () -> Type\n\
Return a const variant of this type." },
  { "fields", exppy_fields, METH_NOARGS,
    "fields () -> list\n\
Return a list holding all the fields of this type.\n\
Each field is a gdb.Field object." },
  { "get", exppy_get, METH_VARARGS,
    "T.get(k[,default]) -> returns field named k in T, if it exists;\n\
otherwise returns default, if supplied, or None if not." },
  { "has_key", exppy_has_key, METH_VARARGS,
    "T.has_key(k) -> True if T has a field named k, else False" },
  { "items", exppy_items, METH_NOARGS,
    "items () -> list\n\
Return a list of (name, field) pairs of this type.\n\
Each field is a gdb.Field object." },
  { "iteritems", exppy_iteritems, METH_NOARGS,
    "iteritems () -> an iterator over the (name, field)\n\
pairs of this type.  Each field is a gdb.Field object." },
  { "iterkeys", exppy_iterkeys, METH_NOARGS,
    "iterkeys () -> an iterator over the field names of this type." },
  { "itervalues", exppy_itervalues, METH_NOARGS,
    "itervalues () -> an iterator over the fields of this type.\n\
Each field is a gdb.Field object." },
  { "keys", exppy_field_names, METH_NOARGS,
    "keys () -> list\n\
Return a list holding all the fields names of this type." },
  { "pointer", exppy_pointer, METH_NOARGS,
    "pointer () -> Type\n\
Return a type of pointer to this type." },
  { "range", exppy_range, METH_NOARGS,
    "range () -> tuple\n\
Return a tuple containing the lower and upper range for this type."},
  { "reference", exppy_reference, METH_NOARGS,
    "reference () -> Type\n\
Return a type of reference to this type." },
  { "strip_typedefs", exppy_strip_typedefs, METH_NOARGS,
    "strip_typedefs () -> Type\n\
Return a type formed by stripping this type of all typedefs."},
  { "target", exppy_target, METH_NOARGS,
    "target () -> Type\n\
Return the target type of this type." },
  { "template_argument", exppy_template_argument, METH_VARARGS,
    "template_argument (arg, [block]) -> Type\n\
Return the type of a template argument." },
  { "unqualified", exppy_unqualified, METH_NOARGS,
    "unqualified () -> Type\n\
Return a variant of this type without const or volatile attributes." },
  { "values", exppy_values, METH_NOARGS,
    "values () -> list\n\
Return a list holding all the fields of this type.\n\
Each field is a gdb.Field object." },
  { "volatile", exppy_volatile, METH_NOARGS,
    "volatile () -> Type\n\
Return a volatile variant of this type" },
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

static PyMappingMethods exppy_mapping = {
  exppy_length,
  exppy_getitem,
  NULL				  /* no "set" method */
};

PyTypeObject expression_object_type =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.Type",			  /*tp_name*/
  sizeof (expression_object),		  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  exppy_dealloc,			  /*tp_dealloc*/
  0,				  /*tp_print*/
  0,				  /*tp_getattr*/
  0,				  /*tp_setattr*/
  0,				  /*tp_compare*/
  0,				  /*tp_repr*/
  &expression_object_as_number,	  /*tp_as_number*/
  0,				  /*tp_as_sequence*/
  &exppy_mapping,		  /*tp_as_mapping*/
  0,				  /*tp_hash */
  0,				  /*tp_call*/
  exppy_str,			  /*tp_str*/
  0,				  /*tp_getattro*/
  0,				  /*tp_setattro*/
  0,				  /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,  /*tp_flags*/
  "GDB type object",		  /* tp_doc */
  0,				  /* tp_traverse */
  0,				  /* tp_clear */
  exppy_richcompare,		  /* tp_richcompare */
  0,				  /* tp_weaklistoffset */
  exppy_iter,			  /* tp_iter */
  0,				  /* tp_iternext */
  expression_object_methods,		  /* tp_methods */
  0,				  /* tp_members */
  expression_object_getset,		  /* tp_getset */
  0,				  /* tp_base */
  0,				  /* tp_dict */
  0,				  /* tp_descr_get */
  0,				  /* tp_descr_set */
  0,				  /* tp_dictoffset */
  0,				  /* tp_init */
  0,				  /* tp_alloc */
  0,				  /* tp_new */
};

static PyGetSetDef field_object_getset[] =
{
  { "__dict__", gdb_py_generic_dict, NULL,
    "The __dict__ for this field.", &field_object_type },
  { NULL }
};

PyTypeObject field_object_type =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.Field",			  /*tp_name*/
  sizeof (field_object),	  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  field_dealloc,		  /*tp_dealloc*/
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
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,  /*tp_flags*/
  "GDB field object",		  /* tp_doc */
  0,				  /* tp_traverse */
  0,				  /* tp_clear */
  0,				  /* tp_richcompare */
  0,				  /* tp_weaklistoffset */
  0,				  /* tp_iter */
  0,				  /* tp_iternext */
  0,				  /* tp_methods */
  0,				  /* tp_members */
  field_object_getset,		  /* tp_getset */
  0,				  /* tp_base */
  0,				  /* tp_dict */
  0,				  /* tp_descr_get */
  0,				  /* tp_descr_set */
  offsetof (field_object, dict),  /* tp_dictoffset */
  0,				  /* tp_init */
  0,				  /* tp_alloc */
  0,				  /* tp_new */
};

PyTypeObject expression_iterator_object_type = {
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.TypeIterator",		  /*tp_name*/
  sizeof (exppy_iterator_object),  /*tp_basicsize*/
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
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,  /*tp_flags*/
  "GDB type iterator object",	  /*tp_doc */
  0,				  /*tp_traverse */
  0,				  /*tp_clear */
  0,				  /*tp_richcompare */
  0,				  /*tp_weaklistoffset */
  exppy_iterator_iter,             /*tp_iter */
  exppy_iterator_iternext,	  /*tp_iternext */
  0				  /*tp_methods */
};
