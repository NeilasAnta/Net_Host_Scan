
<template>
  <div>
      <a-form-model>
          <a-form-model-item label="IP address" required>
              <a-input placeholder="IP address" v-model="ipAddress" required/>
              <p v-if="this.ipMessage">{{this.ipMessage}}</p>
          </a-form-model-item>

          <a-form-model-item label="Netmask" required>
              <a-input placeholder="Netmask" v-model="netmask" required/>
              <p v-if="this.netmaskMessage">{{this.netmaskMessage}}</p>
          </a-form-model-item>

          <a-form-model-item label="Open Port Scan:">
              <a-switch v-model="portScan"/>
              <br/>
              <a-input-number :min="1" :max="65535" v-if="portScan" placeholder="Port from" v-model="portFrom"/>
              <br/>
              <a-input-number :min="1" :max="65535" v-if="portScan" placeholder="Port to" v-model="portTo"/>
          </a-form-model-item>

        <a-form-model-item>
          <div style="text-align: center">
            <a-button type="submit" class="primary" style="margin-right: 10px" @click="validate">Search</a-button>
          </div>
        </a-form-model-item>

        <p v-if="message">{{message}}</p>
    </a-form-model>

      <table v-if="this.hosts!=null">
        <tr>
          <th>IP Address: </th>
          <th>MAC address: </th>
          <th v-show="portScan">Open ports: </th>
        </tr>
        <tr v-for="(host, index) in hosts" :key="index">
          <td>{{ host.ipNumber }}</td>
          <td>{{ host.macAddr }}</td>
          <td>{{ host.openPorts }}</td>
        </tr>
      </table>
  </div>
</template>

<script>
export default {
data () {
    return {
      portScan: false,
      ipAddress: '',
      netmask: '',
      portFrom: '',
      portTo: '',
      inetrval: null,
      hosts: null,
      ipMessage: '',
      netmaskMessage: '',
      message: '',
    }
  },
  created(){
    this.$spin(false)
  },
  methods:{
    validate(){
      this.ipMessage = ''
      this.netmaskMessage = ''
      let flag = false
      let ipRegex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$/g
      if(this.ipAddress != '' && this.ipAddress.match(ipRegex)){
        flag = true
      }else{
        this.ipMessage = 'Bad IP address'
      }

      if(!(flag && parseInt(this.netmask) >= 1 && parseInt(this.netmask) <= 32))
      {
        flag = false
        this.netmaskMessage = 'Bad netmask'
      }

      if(flag)
      {
        this.doSearch()
      }
    },
     async doSearch(){
      this.hosts = null
        let flag = false
        await this.$rpc.call('scan', 'do_search', { ip: this.ipAddress, netmask: this.netmask, openPorts: this.portScan, from: this.portFrom, to: this.portTo}).then(({ status, message }) => {
            if(status === 'ok'){
                flag = true
            }
        })
        if (flag){
          this.message = "Scaning!!"
          this.inetrval = setInterval(() =>  {
          let call = this.$rpc.call('scan', 'get_search_results', {}, 15000).then(({ status, message, list }) => {
                console.log(message)
                if(list != null && status === 'ok'){
                    this.hosts = list                   
                    this.message = "Done!!"
                    clearInterval(this.inetrval)
                }  
                if(status === 'error')
                {
                    this.message = message
                    clearInterval(this.inetrval)
                }          
            })
        }, 1500);
        }        
    }, 
    test(){
      alert("asdasda")
    }
  }
}
</script>