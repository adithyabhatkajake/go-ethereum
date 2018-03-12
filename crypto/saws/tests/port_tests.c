#define TARGET "Import/Export Test"

#include <handlefile.h>
#include <audit.h>
#include <port.h>
#include <test.h>

int main(int argc, char* argv[])
{
    log_level = LOG_TRACE;
    struct keypair_t* kpair;
    struct file_t *f = get_file_blocks(argv[1]);

    generate_parity(f);

    char* pvt_filename = "private-key.sig";
    char* pub_filename = "public-key.sig";
    char* file_test    = "file.dat";
    char* query_file   = "query.dat";

    tag_param_t params;

    kpair = generate_key_pair();

    params.pairing = kpair->pvt_key->pairing;
    params.alpha = kpair->pvt_key->alpha;
    params.secret_x = kpair->pvt_key->x;

    set_tags(f,&params);

    // export_pvt_key(kpair->pvt_key,pvt_filename);
    // struct private_key_t* pkey = import_pvt_key(pvt_filename);
    // export_public_key(kpair->pub_key,pub_filename);
    struct public_key_t* pubkey = import_public_key(pub_filename);
    // export_file(f,file_test);
    // struct file_t* f2 = import_file(file_test);

    // element_printf("PrivateKey\n%B\n%B\n%B\n",pkey->alpha,pkey->g,pkey->x);
    element_printf("Public Key\n%B\n%B\n%B\n",pubkey->alpha,pubkey->g,pubkey->v);
    // element_printf("%B\n%B\n",pkey->x,kpair->pvt_key->x);
    // element_printf("%B\n%B\n",pubkey->v,kpair->pub_key->v);
    // printf("%d\n",element_cmp(kpair->pvt_key->alpha,pkey->alpha));
    // printf("%d\n",element_cmp(kpair->pvt_key->g,pkey->g));
    // printf("%d\n",element_cmp(kpair->pvt_key->x,pkey->x));
    // printf("%d\n",element_cmp(kpair->pub_key->alpha,pubkey->alpha));
    // printf("%d\n",element_cmp(kpair->pub_key->g,pubkey->g));
    // printf("%d\n",element_cmp(kpair->pub_key->v,pubkey->v));

    // struct query_t query_obj = {
        // .query_length = 3,
    // };

    // query_obj.pairing   = pkey->pairing;
    // query_obj.indices   = (uint32_t*)malloc(sizeof(uint32_t) * query_obj.query_length);
    // query_obj.nu        = (struct element_s*)malloc(sizeof(struct element_s) * query_obj.query_length);

    // query_obj.indices[0] = 0;
    // query_obj.indices[1] = 1;
    // query_obj.indices[2] = 2;

    // for(uint32_t i=0;i<query_obj.query_length;i++) {
        // element_init_Zr(query_obj.nu+i,pkey->pairing);
        // element_random(query_obj.nu+i);
    // }
    
    // export_query(&query_obj,query_file);
    // struct query_t* query_obj2 = import_query(query_file);

    // struct query_response_t* response1 = query(f,query_obj);
    // struct query_response_t* response2 = query(f,*query_obj2);
    // struct query_response_t* response3 = query(f,query_obj);
    //Log(LOG_TRACE,"Sigma:%B\nMu:%B\n",response->sigma,response->mu);

    // enum audit_result result1 = verify_storage(f,*response1,query_obj,  pkey->g,params.alpha,pubkey->v);
    // unsigned int result2 = verify_storage(f,*response2,*query_obj2,kpair->pvt_key->g,params.alpha,kpair->pub_key->v);
    // int result3 = verify_storage(f,*response3,query_obj,pkey->g,params.alpha,pubkey->v);


    // Log(LOG_TRACE,"Response: %d %d\n",result1==PASS?0:1,result1==PASS?0:1);

    EXIT_TEST();
    
    // free(query_obj.indices);
    // free(query_obj.nu);
    // free_keypair(kpair);
    // free(kpair);

    return 0;
}