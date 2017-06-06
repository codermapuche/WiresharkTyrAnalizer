/*/
 * @author Nehuen Prados <nehuensd@gmail.com>
 * @date 07/06/2017
 * @version 1.1
 * @licence Public Domain
/*/

const TyrAnalizer = (function(window, undefined) {

  function TyrAnalizer(capture, options) {
    const analizer = this;

    analizer.history = options.history;
    analizer.graph = options.graph;

    this.loadCapture(capture);
  }

  /*/ Load a Wireshark .json capture file. /*/
  TyrAnalizer.prototype.loadCapture = function(path) {
    const analizer = this;

    analizer.capture = {
      path: path,
      data: null,
      info: null
    }

    var loadData = new Promise(function(resolve, reject) {
      var request = new XMLHttpRequest();

      request.onreadystatechange = function() {
        if (request.readyState == 4) {
          if (request.status == 200) {
            var data = null;
            try {
              data = JSON.parse(request.responseText);
              resolve(data);
            } catch (err) {
              console.log(request.responseText);
              reject(err);
            }
          } else {
            reject(request);
          }
        }
      }

      request.open("GET", path, true);
      request.send();
    });

    loadData
      .then(function(data) {
        analizer.capture.data = data;
        analizer.initAnalizer();
      })
      .catch(function(error) {
        console.log(error);
      });
  }

  /*/ Init a pseudo-heuristic analizer. /*/
  TyrAnalizer.prototype.initAnalizer = function() {
    const analizer = this;

    // Init table history with headers.
    analizer.history.innerHTML = "<thead><tr><th>#</th><th>Protocolo</th><th>Origen</th><th>Destino</th><th>Mensaje</th></tr></thead>";

    // Parse raw data.
    analizer.capture.traffic = TyrAnalizer.parseTraffic(analizer.capture.data.map(TyrAnalizer.parsePacket));

    // Analize topology
    var nodes = analizer.graph.querySelectorAll(".node"),
        networks = analizer.graph.querySelectorAll(".network[data-broad]");

    analizer.topologyTable = {
      indexMac: {},
      indexIp: {},
      interfaces: {}
    }

    // Autoparse ARP
    analizer.capture.traffic
      .filter(function(packet) {
        return packet.protocol.lastIndexOf("arp") === packet.protocol.length - 3;
      })
      .forEach(function(packet) {
        analizer.topologyTable.indexMac[packet.sourceMac] = packet.sourceIp;
        analizer.topologyTable.indexIp[packet.sourceIp] = packet.sourceMac;
      });

    // Populate graph data
    for (var nro=networks.length-1; nro >= 0; nro--) {
      var networkNodes = networks[nro].querySelectorAll(".node");
      for (var nNro=networkNodes.length-1; nNro >= 0; nNro--) {
        networkNodes[nNro].dataset.broad = (networkNodes[nNro].dataset.broad ? networkNodes[nNro].dataset.broad + "-" : "") +
                                            networks[nro].dataset.broad;
      }
    }

    // Index interfaces
    for (var nro=nodes.length-1; nro >= 0; nro--) {
      var node = {
        name:  nodes[nro].querySelector("label strong").innerHTML,
        icon:  nodes[nro].querySelector("i").className,
        ips:   nodes[nro].dataset.ip.split("-"),
        broad: (nodes[nro].dataset.broad ? nodes[nro].dataset.broad.split("-") : [])
      }

      // Remove duplicates and self-broadcast
      node.broad = node.broad.filter(function(ip, pos) {
        return node.broad.indexOf(ip) === pos && node.ips.indexOf(ip) === -1;
      });

      node.ips.forEach(function(ip) {
        if (!analizer.topologyTable.indexIp[ip]) {
          console.warn("IP INTERFACE: " + ip + " not be present in ARP messages.");
          return;
        }

        analizer.topologyTable.interfaces[analizer.topologyTable.indexIp[ip]] = node;
      });
    }


    // Populate history table.
    analizer.history.innerHTML += "<tbody><tr>" +
                                  analizer.capture.traffic.map(function(packet, idx) {
                                    return "<td>" +
                                           [
                                            idx + 1,
                                            TyrAnalizer.makeTemplate(packet, "protocol", analizer.topologyTable),
                                            TyrAnalizer.makeTemplate(packet, "source", analizer.topologyTable),
                                            TyrAnalizer.makeTemplate(packet, "target", analizer.topologyTable),
                                            TyrAnalizer.makeTemplate(packet, "message", analizer.topologyTable),
                                           ]
                                           .join("</td><td>") +
                                           "</td>";
                                  })
                                  .join("</tr><tr>") +
                                  "</tr></tbody>";
  }

  /*/ Parse individual packet. /*/
  TyrAnalizer.parsePacket = function parsePacket(packet) {
    var info = {};
    info.protocol = packet._source.layers.frame["frame.protocols"];
    
    if (info.protocol.indexOf("http:data-text-lines") !== -1) {
      info.protocol = info.protocol.replace("http:data-text-lines", "http");
    }      
    
    if (packet._source.layers.eth) {
      // It has Ethernet info
      info.sourceMac = packet._source.layers.eth["eth.src"];
      info.targetMac = packet._source.layers.eth["eth.dst"];
    }

    if (packet._source.layers.ip) {
      // It has IP info
      info.sourceIp = packet._source.layers.ip["ip.src"];
      info.targetIp = packet._source.layers.ip["ip.dst"];
    }

    if (packet._source.layers.tcp) {
      // It has TCP info
      info.sourcePort = packet._source.layers.tcp["tcp.srcport"];
      info.targetPort = packet._source.layers.tcp["tcp.dstport"];

      info.ack = packet._source.layers.tcp["tcp.ack"];
      info.flags = {
        syn: packet._source.layers.tcp["tcp.flags_tree"]["tcp.flags.syn"] === "1",
        ack: packet._source.layers.tcp["tcp.flags_tree"]["tcp.flags.ack"] === "1",
        fin: packet._source.layers.tcp["tcp.flags_tree"]["tcp.flags.fin"] === "1"
      };

    }

    if (packet._source.layers.udp) {
      // It has UDP info
      info.sourcePort = packet._source.layers.udp["udp.srcport"];
      info.targetPort = packet._source.layers.udp["udp.dstport"];
    }

    if (packet._source.layers.arp) {
      // It has ARP info
      info.sourceMac = packet._source.layers.arp["arp.src.hw_mac"];

      // Broadcast is "ff:ff:ff:ff:ff:ff" like Ethernet
      if (packet._source.layers.arp["arp.dst.hw_mac"] !== "00:00:00:00:00:00") {
        info.targetMac = packet._source.layers.arp["arp.dst.hw_mac"];
      }

      info.sourceIp = packet._source.layers.arp["arp.src.proto_ipv4"];
      info.targetIp = packet._source.layers.arp["arp.dst.proto_ipv4"];

      info.opcode = packet._source.layers.arp["arp.opcode"];
    }

    if (packet._source.layers.http) {
      // It has HTTP info
      info.message = Object.keys(packet._source.layers.http)[0];
      if (info.message.indexOf("GET ") === 0) {
        info.url = info.message.split(" ")[1];
      } else if (info.message.indexOf("HTTP") === 0) {
        if (info.message.split(" ")[1] === "200") {   
          info.data = packet._source.layers.http["http.file_data"];
        }
      }
    }

    if (packet._source.layers.dns) {
      // It has DNS info
      if (packet._source.layers.dns["dns.count.queries"] !== "0") {
        info.query = Object.keys(packet._source.layers.dns.Queries)[0];        
      }
      
      if (packet._source.layers.dns["dns.count.answers"] !== "0") {
        info.answer = Object.keys(packet._source.layers.dns.Answers)[0];        
      }
      
      if (packet._source.layers.dns["dns.count.auth_rr"] !== "0") {
        info.aNameservers = Object.keys(packet._source.layers.dns["Authoritative nameservers"])[0];        
      }
      
      if (packet._source.layers.dns["dns.count.add_rr"] !== "0") {
        info.aRecords = Object.keys(packet._source.layers.dns["Additional records"])[0];        
      }
      
    }
    
    return info;
  }

  /*/ Parse global traffic. /*/
  TyrAnalizer.parseTraffic = function parseTraffic(traffic) {

    // No traffic.
    if (traffic.length === 0) {
      return traffic;
    }

    // Clean common protocol prefix
    var commonPrefix = traffic[0].protocol;
    for (var pos = traffic.length - 1; pos > 0; pos--) {
      if (traffic[pos].protocol.indexOf(commonPrefix) === 0) {
        continue;
      }

      // commonPrefix not be here
      var lastPartIndex = commonPrefix.lastIndexOf(":");
      if (lastPartIndex === -1) {
        break;
      }

      // Start a search of subpart
      commonPrefix = commonPrefix.substr(0, commonPrefix.lastIndexOf(":"));
      pos = traffic.length - 1;
    }

    if (pos === 0 && commonPrefix !== "") {
      traffic = traffic.map(function(packet) {
        packet.protocol = packet.protocol.replace(commonPrefix + ":", "");
        return packet;
      });
    }

    return traffic;

  }

  /*/ Make template of property. /*/
  TyrAnalizer.makeTemplate = function makeTemplate(packet, field, topology) {
    switch (field) {
      case "source":
        var name = "<i class=\"" + topology.interfaces[packet.sourceMac].icon + "\"></i>" +
                 "<strong>" + topology.interfaces[packet.sourceMac].name + "</strong>" +
                 (packet.sourceIp ? "<strong>" + packet.sourceIp + (packet.sourcePort ? "<span>" + packet.sourcePort + "</span>" : "") + "</strong>" : "<br>") +
                "<em>" + packet.sourceMac + "</em>"
        return name;
        break;
      case "target":
        var name;

        if (packet.targetMac === "ff:ff:ff:ff:ff:ff") {
          name = "<strong>BROADCAST</strong>";
        } else {
          name = "<i class=\"" + topology.interfaces[packet.targetMac].icon + "\"></i>" +
                 "<strong>" + topology.interfaces[packet.targetMac].name + "</strong>" +
                 (packet.targetIp ? "<strong>" + packet.targetIp + (packet.targetPort ? "<span>" + packet.targetPort + "</span>" : "") + "</strong>" : "<br>");
        }

        name += "<em>" + packet.targetMac + "</em>";

        return name;
        break;
      case "message":
        var message = "",
            protocol = packet.protocol.lastIndexOf(":") !== -1 ? packet.protocol.substr(packet.protocol.lastIndexOf(":") + 1) : packet.protocol;

        switch (protocol) {
          case "arp":
            if (packet.opcode === "1") {

              message = "El <em>" + topology.interfaces[packet.sourceMac].name  + "</em> pregunta:<br>¿Quien tiene esta IP? <strong>" + packet.targetIp + "</strong>";
            } else {
              message = "El <em>" + topology.interfaces[packet.sourceMac].name  + "</em> contesta:<br>¡Yo tengo esa IP! <strong>" + packet.sourceIp + "</strong>";
            }
            break;
          case "tcp":
            if (packet.flags.syn) {
              if (packet.flags.ack) {
                message = "El <em>" + topology.interfaces[packet.sourceMac].name  + "</em> contesta:<br>Dale, ¿y abrimos esta tambien? <strong>" + packet.sourceIp + "<span>" + packet.sourcePort + "</span> → " + packet.targetIp + "<span>" + packet.targetPort + "</span></strong>";
              } else {
                message = "El <em>" + topology.interfaces[packet.sourceMac].name  + "</em> pregunta:<br>¿Abrimos esta conexion? <strong>" + packet.sourceIp + "<span>" + packet.sourcePort + "</span> → " + packet.targetIp + "<span>" + packet.targetPort + "</span></strong>";
              }
            } else if (packet.flags.ack) {
              message = "El <em>" + topology.interfaces[packet.sourceMac].name  + "</em> contesta:<br>Si dale.";
            }
            break;
          case "http": 
            if (packet.message.indexOf("GET ") === 0) {
              message = "El <em>" + topology.interfaces[packet.sourceMac].name  + "</em> pide el recurso:<br><strong><span>" + packet.url + "</span></strong>";
            } else if (packet.data) {
              message = "El <em>" + topology.interfaces[packet.sourceMac].name  + "</em> envia el recurso:<br>" + 
                        "<iframe sandbox srcdoc=\"" + 
                        packet.data        
                          .replace(/img src\=\"/gi, 'img data-src="')
                          .replace(/&/g, '&amp;')
                          .replace(/>/g, '&gt;')
                          .replace(/</g, '&lt;')
                          .replace(/"/g, '&quot;')
                          .replace(/'/g, '&apos;')  +
                        "\"></iframe>";
            } else {
              console.log(packet)
            }
            break;
          case "dns": 
            if (packet.answer || packet.aNameservers || packet.aRecords) {   
              message = "El <em>" + topology.interfaces[packet.sourceMac].name  + "</em> le responde a <em>" + topology.interfaces[packet.targetMac].name  + "</em> la pregunta:<br><strong><span>" + packet.query + "</span></strong>";    
              if (packet.answer) {
                message += "<br>La respuesta es:<br><strong><span>" + packet.answer + "</span></strong>";
              }        
              if (packet.aNameservers) {
                message += "<br>Los servidores de nombres con autoridad:<br><strong><span>" + packet.aNameservers + "</span></strong>";
              }        
              if (packet.aRecords) {
                message += "<br>Los registros adicionales:<br><strong><span>" + packet.aRecords + "</span></strong>";                
              }        
            } else {
              message = "El <em>" + topology.interfaces[packet.sourceMac].name  + "</em> pregunta por:<br><strong><span>" + packet.query + "</span></strong>";             
            }
            break;
        }

        return message;
        break;
      default:
        return packet[field];
        break;
    }
  }

  return TyrAnalizer;

})(window);


/*/ ============================================= /*/