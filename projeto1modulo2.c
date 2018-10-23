#include <linux/init.h>           
#include <linux/module.h>         
#include <linux/device.h>         
#include <linux/kernel.h>         
#include <linux/fs.h>             
#include <linux/uaccess.h>    
#include <crypto/internal/skcipher.h>
#include <linux/crypto.h>     

#define  DEVICE_NAME "crypto"
#define  CLASS_NAME  "cryptoClass"    

MODULE_LICENSE("GPL");            
      
static int    majorNumber;                  
static char   message[256] = {0};           
static short  size_of_message; // tamanho da mensagem              
static struct class*  cryptoClass  = NULL; 
static struct device* cryptoDevice = NULL; 
static char *key;

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave para receber");

static int	dev_open(struct inode *, struct file *);
static int	dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static char Hexa2Dec(int numeroEntrada);

static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};

struct tcrypt_result {
	struct completion completion;
	int err;
};

struct skcipher_def {
	struct scatterlist sg;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct tcrypt_result result;
	char * scratchpad;
	char * ciphertext;
	char * ivdata;
	unsigned int encrypt;
};

struct skcipher_def sk;

// Prototipos de funções:
static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc);
static void test_skcipher_cb(struct crypto_async_request *req, int error);

static int __init crypto_init(void){
   printk(KERN_INFO "cryptodevice: inicializado com sucesso! com chave = %s\n", key);

	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   	if (majorNumber<0){
      		printk(KERN_ALERT "cryptodevice falha ao criar major number\n");
      		return majorNumber;
   	}
   	printk(KERN_INFO "cryptodevice: major number criado = %d\n", majorNumber);

   // Register the device class
	   cryptoClass = class_create(THIS_MODULE, CLASS_NAME);
	   if (IS_ERR(cryptoClass)){                
	   	unregister_chrdev(majorNumber, DEVICE_NAME);
	   	printk(KERN_ALERT "Falha ao criar classe de devide\n");
	   	return PTR_ERR(cryptoClass);     
	   }
	   printk(KERN_INFO "Classe criada com sucesso\n");

   // Register the device driver
   cryptoDevice = device_create(cryptoClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(cryptoDevice)){            
      class_destroy(cryptoClass);           
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Falha ao criar device\n");
      return PTR_ERR(cryptoDevice);
   }
   printk(KERN_INFO "Device criado com sucesso\n"); 
   return 0;
}

static void __exit crypto_exit(void){
   device_destroy(cryptoClass, MKDEV(majorNumber, 0));
   class_unregister(cryptoClass);                          
   class_destroy(cryptoClass);                             
   unregister_chrdev(majorNumber, DEVICE_NAME);             
   printk(KERN_INFO "cryptoDevice: Finalizado!\n");
}

static int dev_open(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "cryptoDevice: Aberto!\n");
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0){
      printk(KERN_INFO "cryptoModule: Eviado %d caracteres para o usuario\n", size_of_message);
      return (size_of_message=0);
   }
   else {
      printk(KERN_INFO "cryptoModule: Falha ao eviar %d caracteres para o usuario\n", error_count);
      return -EFAULT;
   }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
	
	
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char *ivdata = NULL;
	char operacao = buffer[0];
	char saidaH[256];
	int ret = -EFAULT;
	char *scratchpad = NULL;
	int i;	
	char messageH[256];
	char saidaF[256];
	sprintf(message, "%s", &(buffer[2]));
  	size_of_message = strlen(message);                 
  	printk(KERN_INFO "cryptoModule: Recebido %zu caracteres do usuario\n", len);
   
	
	skcipher = crypto_alloc_skcipher("ecb-aes-aesni", 0, 0);
	if (IS_ERR(skcipher)) {
      		pr_info("cryptoModule: nao foi possivel alocar handle\n");
       		return PTR_ERR(skcipher);
    	}
	 req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    	if (!req) {
		pr_info("could not allocate skcipher request\n");
    	}
	
	sk.tfm = skcipher;
	sk.req = req;
	
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      test_skcipher_cb,
                      &sk.result);
	ivdata = kmalloc(16, GFP_KERNEL);
   	if (!ivdata) {
      		pr_info("Nao foi possivel alocar o ivdata\n");
    	}

	if (crypto_skcipher_setkey(skcipher, key, 16) != 0) {
     		pr_info("cryptodevice: não foi possível definir a chave\n");
   	}
   
   printk(KERN_INFO "cryptoModule: Mensagem recebida antes da operacao:%s\n", message);
   
		scratchpad = kmalloc(16, GFP_KERNEL);
		if (!scratchpad) {
			printk("cryptoModule: Nao foi possivel alocar o Scratchpad\n");
			return ret;
		}

	switch(operacao){
	
	case 'c':
		printk(KERN_INFO "cryptoModule: FUNCAO C\n");
		    /* We encrypt one block */

		 for(i = 0; i<size_of_message; i++){
     		   sprintf(messageH+i*2, "%02X", message[i]);
    		}
		printk(KERN_INFO "cryptoModule: message:%s e messageH:%s\n", message,messageH);
	
		for(i=0;i<size_of_message/8;i++){
		memcpy(scratchpad,messageH+16*i,16);	
		
		sg_init_one(&sk.sg, scratchpad, 16);
		skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata);
		init_completion(&sk.result.completion);
		
		
		ret = test_skcipher_encdec(&sk, 1);

   		memcpy(saidaH+16*i,scratchpad,16);
  
		}

		printk(KERN_INFO "cryptoModule: ret:%d\n",ret);
		printk(KERN_INFO "cryptoModule: saidaF:%s\n",saidaF);
		printk(KERN_INFO "cryptoModule: Mensagem enviada depois da operacao:%s\n", saidaH);

		
		break;
	case 'd':
		printk(KERN_INFO "cryptoModule: FUNCAO D\n");

	
		for(i=0;i<size_of_message/8;i++){
		memcpy(scratchpad,saidaH+16*i,16);	
		
		sg_init_one(&sk.sg, scratchpad, 16);
		skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata);
		init_completion(&sk.result.completion);
		
		
		ret = test_skcipher_encdec(&sk, 0);

   		memcpy(saidaH+16*i,scratchpad,16);
  
		}
 		for(i = 0; i<size_of_message; i++){
			sprintf(&saidaF[i * 2], "%x", messageH[i]);
    		}
		printk(KERN_INFO "cryptoModule: ret:%d\n",ret);
		printk(KERN_INFO "cryptoModule: saidaF:%s\n",saidaF);
		printk(KERN_INFO "cryptoModule: Mensagem enviada depois da operacao:%s\n", saidaH);
		
		break;
	case 'h':
		printk(KERN_INFO "cryptoModule: FUNCAO H\n");
		break;
	default:
		break;
	}
 
   return len;

   
}


static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "cryptoModule: Device fechado com sucesso!\n");
   return 0;
}

static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc)
{
    int rc = 0;

    if (enc)
        rc = crypto_skcipher_encrypt(sk->req);
    else
        rc = crypto_skcipher_decrypt(sk->req);

    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n",
            rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}

static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS)
        return;
    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
}

static char Hexa2Dec(int numeroEntrada){
	int q, resto;
	char exa[100], getInt[100];
	
	
	do{
		q = numeroEntrada / 16;
		resto = numeroEntrada % 16;
		numeroEntrada /= 16;
		
		switch(resto){
			case 10:
				strcat(exa, "A");
			break;
			case 11:
				strcat(exa, "B");
			break;
			case 12:
				strcat(exa, "C");
			break;
			case 13:
				strcat(exa, "D");
			break;
			case 14:
				strcat(exa, "E");
			break;
			case 15:
				strcat(exa, "F");
			break;
			case 16:
				strcat(exa, "G");
			break;
			default:
				sprintf(getInt, "%i", resto);
				strcat(exa, getInt);
		}
	}while(q != 0);
	return exa;
}

module_init(crypto_init);
module_exit(crypto_exit);
