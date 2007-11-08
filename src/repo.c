/*
 * Copyright (c) 2007, Novell Inc.
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

/*
 * repo.c
 *
 * Manage metadata coming from one repository
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "repo.h"
#include "pool.h"
#include "poolid_private.h"
#include "util.h"

#define IDARRAY_BLOCK     4095


/*
 * create empty repo
 * and add to pool
 */

Repo *
pool_addrepo_empty(Pool *pool)
{
  Repo *repo;

  pool_freewhatprovides(pool);
  repo = (Repo *)xcalloc(1, sizeof(*repo));
  pool->repos = (Repo **)xrealloc(pool->repos, (pool->nrepos + 1) * sizeof(Repo *));
  pool->repos[pool->nrepos++] = repo;
  repo->name = "empty";
  repo->pool = pool;
  repo->start = pool->nsolvables;
  repo->nsolvables = 0;
  return repo;
}

/*
 * add Id to repo
 * olddeps = old array to extend
 * 
 */

Offset
repo_addid(Repo *repo, Offset olddeps, Id id)
{
  Id *idarray;
  int idarraysize;
  int i;
  
  idarray = repo->idarraydata;
  idarraysize = repo->idarraysize;

  if (!idarray)			       /* alloc idarray if not done yet */
    {
      idarray = (Id *)xmalloc((1 + IDARRAY_BLOCK) * sizeof(Id));
      idarray[0] = 0;
      idarraysize = 1;
      repo->lastoff = 0;
    }

  if (!olddeps)				/* no deps yet */
    {   
      olddeps = idarraysize;
      if ((idarraysize & IDARRAY_BLOCK) == 0)
        idarray = (Id *)xrealloc(idarray, (idarraysize + 1 + IDARRAY_BLOCK) * sizeof(Id));
    }   
  else if (olddeps == repo->lastoff)	/* extend at end */
    idarraysize--;
  else					/* can't extend, copy old */
    {
      i = olddeps;
      olddeps = idarraysize;
      for (; idarray[i]; i++)
        {
          if ((idarraysize & IDARRAY_BLOCK) == 0)
            idarray = (Id *)xrealloc(idarray, (idarraysize + 1 + IDARRAY_BLOCK) * sizeof(Id));
          idarray[idarraysize++] = idarray[i];
        }
      if ((idarraysize & IDARRAY_BLOCK) == 0)
        idarray = (Id *)xrealloc(idarray, (idarraysize + 1 + IDARRAY_BLOCK) * sizeof(Id));
    }
  
  idarray[idarraysize++] = id;		/* insert Id into array */

  if ((idarraysize & IDARRAY_BLOCK) == 0)   /* realloc if at block boundary */
    idarray = (Id *)xrealloc(idarray, (idarraysize + 1 + IDARRAY_BLOCK) * sizeof(Id));

  idarray[idarraysize++] = 0;		/* ensure NULL termination */

  repo->idarraydata = idarray;
  repo->idarraysize = idarraysize;
  repo->lastoff = olddeps;

  return olddeps;
}


/*
 * add dependency (as Id) to repo
 * olddeps = offset into idarraydata
 * isreq = 0 for normal dep
 * isreq = 1 for requires
 * isreq = 2 for pre-requires
 * 
 */

Offset
repo_addid_dep(Repo *repo, Offset olddeps, Id id, int isreq)
{
  Id oid, *oidp, *marker = 0;

  if (!olddeps)
    return repo_addid(repo, olddeps, id);

  if (!isreq)
    {
      for (oidp = repo->idarraydata + olddeps; (oid = *oidp) != ID_NULL; oidp++)
	{
	  if (oid == id)
	    return olddeps;
	}
      return repo_addid(repo, olddeps, id);
    }

  for (oidp = repo->idarraydata + olddeps; (oid = *oidp) != ID_NULL; oidp++)
    {
      if (oid == SOLVABLE_PREREQMARKER)
	marker = oidp;
      else if (oid == id)
	break;
    }

  if (oid)
    {
      if (marker || isreq == 1)
        return olddeps;
      marker = oidp++;
      for (; (oid = *oidp) != ID_NULL; oidp++)
        if (oid == SOLVABLE_PREREQMARKER)
          break;
      if (!oid)
        {
          oidp--;
          if (marker < oidp)
            memmove(marker, marker + 1, (oidp - marker) * sizeof(Id));
          *oidp = SOLVABLE_PREREQMARKER;
          return repo_addid(repo, olddeps, id);
        }
      while (oidp[1])
        oidp++;
      memmove(marker, marker + 1, (oidp - marker) * sizeof(Id));
      *oidp = id;
      return olddeps;
    }
  if (isreq == 2 && !marker)
    olddeps = repo_addid(repo, olddeps, SOLVABLE_PREREQMARKER);
  else if (isreq == 1 && marker)
    {
      *marker++ = id;
      id = *--oidp;
      if (marker < oidp)
        memmove(marker + 1, marker, (oidp - marker) * sizeof(Id));
      *marker = SOLVABLE_PREREQMARKER;
    }
  return repo_addid(repo, olddeps, id);
}


/*
 * reserve Ids
 * make space for 'num' more dependencies
 */

Offset
repo_reserve_ids(Repo *repo, Offset olddeps, int num)
{
  num++;	/* room for trailing ID_NULL */

  if (!repo->idarraysize)	       /* ensure buffer space */
    {
      repo->idarraysize = 1;
      repo->idarraydata = (Id *)xmalloc(((1 + num + IDARRAY_BLOCK) & ~IDARRAY_BLOCK) * sizeof(Id));
      repo->idarraydata[0] = 0;
      repo->lastoff = 1;
      return 1;
    }

  if (olddeps && olddeps != repo->lastoff)   /* if not appending */
    {
      /* can't insert into idarray, this would invalidate all 'larger' offsets
       * so create new space at end and move existing deps there.
       * Leaving 'hole' at old position.
       */
      
      Id *idstart, *idend;
      int count;

      for (idstart = idend = repo->idarraydata + olddeps; *idend++; )   /* find end */
	;
      count = idend - idstart - 1 + num;	       /* new size */

      /* realloc if crossing block boundary */
      if (((repo->idarraysize - 1) | IDARRAY_BLOCK) != ((repo->idarraysize + count - 1) | IDARRAY_BLOCK))
	repo->idarraydata = (Id *)xrealloc(repo->idarraydata, ((repo->idarraysize + count + IDARRAY_BLOCK) & ~IDARRAY_BLOCK) * sizeof(Id));

      /* move old deps to end */
      olddeps = repo->lastoff = repo->idarraysize;
      memcpy(repo->idarraydata + olddeps, idstart, count - num);
      repo->idarraysize = olddeps + count - num;

      return olddeps;
    }

  if (olddeps)			       /* appending */
    repo->idarraysize--;

  /* realloc if crossing block boundary */
  if (((repo->idarraysize - 1) | IDARRAY_BLOCK) != ((repo->idarraysize + num - 1) | IDARRAY_BLOCK))
    repo->idarraydata = (Id *)xrealloc(repo->idarraydata, ((repo->idarraysize + num + IDARRAY_BLOCK) & ~IDARRAY_BLOCK) * sizeof(Id));

  /* appending or new */
  repo->lastoff = olddeps ? olddeps : repo->idarraysize;

  return repo->lastoff;
}


/*
 * remove repo from pool
 * 
 */

void
pool_freerepo(Pool *pool, Repo *repo)
{
  int i, nsolvables;

  pool_freewhatprovides(pool);

  for (i = 0; i < pool->nrepos; i++)	/* find repo in pool */
    {
      if (pool->repos[i] == repo)
	break;
    }
  if (i == pool->nrepos)	       /* repo not in pool, return */
    return;

  /* close gap
   * all repos point into pool->solvables _relatively_ to repo->start
   * so closing the gap only needs adaption of repo->start for all
   * other repos.
   */
  
  nsolvables = repo->nsolvables;
  if (pool->nsolvables > repo->start + nsolvables)
    memmove(pool->solvables + repo->start, pool->solvables + repo->start + nsolvables, (pool->nsolvables - repo->start - nsolvables) * sizeof(Solvable));
  pool->nsolvables -= nsolvables;

  for (; i < pool->nrepos - 1; i++)
    {
      pool->repos[i] = pool->repos[i + 1];   /* remove repo */
      pool->repos[i]->start -= nsolvables;     /* adapt start offset of remaining repos */
    }
  pool->nrepos = i;

  xfree(repo->idarraydata);
  xfree(repo->rpmdbid);
  xfree(repo);
}

Offset
repo_fix_legacy(Repo *repo, Offset provides, Offset supplements)
{
  Pool *pool = repo->pool;
  Id id, idp, idl, idns;
  char buf[1024], *p, *dep;
  int i;

  if (provides)
    {
      for (i = provides; repo->idarraydata[i]; i++)
	{
	  id = repo->idarraydata[i];
	  if (ISRELDEP(id))
	    continue;
	  dep = (char *)id2str(pool, id);
	  if (!strncmp(dep, "locale(", 7) && strlen(dep) < sizeof(buf) - 2)
	    {
	      idp = 0;
	      strcpy(buf + 2, dep);
	      dep = buf + 2 + 7;
	      if ((p = strchr(dep, ':')) != 0 && p != dep)
		{
		  *p++ = 0;
		  idp = str2id(pool, dep, 1);
		  dep = p;
		}
	      id = 0;
	      while ((p = strchr(dep, ';')) != 0)
		{
		  if (p == dep)
		    {
		      dep = p + 1;
		      continue;
		    }
		  strncpy(dep - 9, "language:", 9);
		  *p++ = 0;
		  idl = str2id(pool, dep - 9, 1);
		  if (id)
		    id = rel2id(pool, id, idl, REL_OR, 1);
		  else
		    id = idl;
		  dep = p;
		}
	      if (dep[0] && dep[1])
		{
	 	  for (p = dep; *p && *p != ')'; p++)
		    ;
		  *p = 0;
		  strncpy(dep - 9, "language:", 9);
		  idl = str2id(pool, dep - 9, 1);
		  if (id)
		    id = rel2id(pool, id, idl, REL_OR, 1);
		  else
		    id = idl;
		}
	      if (idp)
		id = rel2id(pool, idp, id, REL_AND, 1);
	      if (id)
		supplements = repo_addid_dep(repo, supplements, id, 0);
	    }
	  else if ((p = strchr(dep, ':')) != 0 && p != dep && p[1] == '/' && strlen(dep) < sizeof(buf))
	    {
	      strcpy(buf, dep);
	      p = buf + (p - dep);
	      *p++ = 0;
	      idp = str2id(pool, buf, 1);
	      idns = str2id(pool, "namespace:installed", 1);
	      id = str2id(pool, p, 1);
	      id = rel2id(pool, idns, id, REL_NAMESPACE, 1);
	      id = rel2id(pool, idp, id, REL_AND, 1);
	      supplements = repo_addid_dep(repo, supplements, id, 0);
	    }
	}
    }
  if (!supplements)
    return 0;
  for (i = supplements; repo->idarraydata[i]; i++)
    {
      id = repo->idarraydata[i];
      if (ISRELDEP(id))
	continue;
      dep = (char *)id2str(pool, id);
      if (!strncmp(dep, "system:modalias(", 16))
	dep += 7;
      if (!strncmp(dep, "modalias(", 9) && dep[9] && dep[10] && strlen(dep) < sizeof(buf))
	{
	  strcpy(buf, dep);
	  p = strchr(buf + 9, ':');
	  idns = str2id(pool, "namespace:modalias", 1);
	  if (p && p != buf + 9 && strchr(p + 1, ':'))
	    {
	      *p++ = 0;
	      idp = str2id(pool, buf + 9, 1);
	      p[strlen(p) - 1] = 0;
	      id = str2id(pool, p, 1);
	      id = rel2id(pool, idns, id, REL_NAMESPACE, 1);
	      id = rel2id(pool, idp, id, REL_AND, 1);
	    }
	  else
	    {
	      p = buf + 9;
	      p[strlen(p) - 1] = 0;
	      id = str2id(pool, p, 1);
	      id = rel2id(pool, idns, id, REL_NAMESPACE, 1);
	    }
	  if (id)
	    repo->idarraydata[i] = id;
	}
      else if (!strncmp(dep, "packageand(", 11) && strlen(dep) < sizeof(buf))
	{
	  strcpy(buf, dep);
	  id = 0;
	  dep = buf + 11;
	  while ((p = strchr(dep, ':')) != 0)
	    {
	      if (p == dep)
		{
		  dep = p + 1;
		  continue;
		}
	      *p++ = 0;
	      idp = str2id(pool, dep, 1);
	      if (id)
		id = rel2id(pool, id, idp, REL_AND, 1);
	      else
		id = idp;
	      dep = p;
	    }
	  if (dep[0] && dep[1])
	    {
	      dep[strlen(dep) - 1] = 0;
	      idp = str2id(pool, dep, 1);
	      if (id)
		id = rel2id(pool, id, idp, REL_AND, 1);
	      else
		id = idp;
	    }
	  if (id)
	    repo->idarraydata[i] = id;
	}
    }
  return supplements;
}

// EOF
