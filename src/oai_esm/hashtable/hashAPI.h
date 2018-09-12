#include"esm_data.h"

struct esm_context_s * esm_get_inplace(struct guti_s guti,struct esm_context_s ** esm_p);
int esm_insert(struct guti_s,struct esm_context_s);
int esm_init(void);
void esm_exit(void);

