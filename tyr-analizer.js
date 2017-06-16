/*/
 * @author Nehuen Prados <nehuensd@gmail.com>
 * @date 07/06/2017
 * @version 1.1
 * @licence Public Domain
/*/

const TyrAnalizer = (function(window, undefined) {

  function TyrAnalizer(capture, options) {
    const analizer = this;

    analizer.protocols = options.protocols;
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
    analizer.history.innerHTML = '<thead><tr><th><input type="checkbox" id="autoplay" checked><label for="autoplay">#</label></th><th>Protocolo</th><th>Origen</th><th>Destino</th><th>Mensaje</th></tr></thead>';
    analizer.protocols.innerHTML = "<thead>" +
                                      "<tr>" +
                                        "<th>Capa 1<br><strong>Fisica</strong></th>" +
                                        "<th>Capa 2<br><strong>Enlace</strong></th>" +
                                        "<th>Capa 3<br><strong>Red</strong></th>" +
                                        "<th>Capa 4<br><strong>Transporte</strong></th>" +
                                        "<th>Capa 5<br><strong>Sesion</strong></th>" +
                                        "<th>Capa 6<br><strong>Presentacion</strong></th>" +
                                        "<th>Capa 7<br><strong>Aplicacion</strong></th>" +
                                      "</tr>" +
                                    "</thead>" +
                                    "<tbody>" +
                                      "<tr>" +
                                        "<td></td>" +
                                        "<td></td>" +
                                        "<td></td>" +
                                        "<td></td>" +
                                        "<td></td>" +
                                        "<td></td>" +
                                        "<td></td>" +
                                      "</tr>" +
                                    "</tbody>";

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
        id:    nodes[nro].querySelector("input").id,
        name:  nodes[nro].querySelector("label strong").innerHTML,
        icon:  nodes[nro].querySelector("i").className,
        ips:   nodes[nro].dataset.ip.split(" "),
        broad: (nodes[nro].dataset.broad ? nodes[nro].dataset.broad.split(" ") : [])
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

    // Populate protocol table.
    analizer.capture.traffic.reduce(function(index, packet) {
      var stack = packet.protocol.split(":");

      for (var nro=0; nro<stack.length; nro++) {
        if (index[stack[nro]]) {
          continue;
        }

        switch (stack[nro]) {
          case "arp":
            analizer.protocols.querySelector("tbody td:nth-child(2)")
                    .innerHTML += '<input type="checkbox" id="protocol-' + stack[nro] + '" checked><label for="protocol-' + stack[nro] + '">' + stack[nro] + '</label>';
            index[stack[nro]] = true;
            break;
          case "ip":
            analizer.protocols.querySelector("tbody td:nth-child(3)")
                    .innerHTML += '<input type="checkbox" id="protocol-' + stack[nro] + '" checked><label for="protocol-' + stack[nro] + '">' + stack[nro] + '</label>';
            index[stack[nro]] = true;
            break;
          case "udp":
          case "tcp":
            analizer.protocols.querySelector("tbody td:nth-child(4)")
                    .innerHTML += '<input type="checkbox" id="protocol-' + stack[nro] + '" checked><label for="protocol-' + stack[nro] + '">' + stack[nro] + '</label>';
            index[stack[nro]] = true;
            break;
          case "http":
          case "dns":
          case "ssl":
            analizer.protocols.querySelector("tbody td:nth-child(7)")
                    .innerHTML += '<input type="checkbox" id="protocol-' + stack[nro] + '" checked><label for="protocol-' + stack[nro] + '">' + stack[nro] + '</label>';
            index[stack[nro]] = true;
            break;
          default:
            console.log(stack[nro]);
            break;
        }
      }

      return index;
    }, {});

    // Populate history table.
    analizer.history.innerHTML += "<tbody><tr>" +
                                  analizer.capture.traffic.map(function(packet, idx) {
                                    return "<td>" +
                                           [
                                            '<input type="radio" name="current-packet" id="packet-' + (idx + 1) + '" '+(idx === 0 ? 'checked' : '')+' data-idx="'+idx+'"><label for="packet-' + (idx + 1) + '">' + (idx + 1) + '</label><a href="#graph">Grafico</a>',
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

    // Show current packet data:
    function updateCurrentPacket() {
      var current = analizer.history.querySelector("input[type='radio'][name='current-packet']:checked"),
          packet = analizer.capture.traffic[current.dataset.idx],
          sourceZone = analizer.graph.querySelector(".messages .source"),
          targetZone = analizer.graph.querySelector(".messages .target"),
          protocolZone = analizer.graph.querySelector(".messages .protocol"),
          messageZone = analizer.graph.querySelector(".messages .message"),
          elements;

      elements = analizer.graph.querySelectorAll('.node.source');
      for(nro=0; nro<elements.length; nro++) {
        elements[nro].classList.remove("source");
      }

      elements = document.querySelectorAll('.node.target');
      for(nro=0; nro<elements.length; nro++) {
        elements[nro].classList.remove("target");
      }

      sourceZone.innerHTML = TyrAnalizer.makeTemplate(packet, "source", analizer.topologyTable);
      targetZone.innerHTML = TyrAnalizer.makeTemplate(packet, "target", analizer.topologyTable);
      protocolZone.innerHTML = TyrAnalizer.makeTemplate(packet, "protocol", analizer.topologyTable);
      messageZone.innerHTML = TyrAnalizer.makeTemplate(packet, "message", analizer.topologyTable);

      elements = analizer.graph.querySelectorAll("[data-ip*='" + analizer.topologyTable.indexMac[packet.sourceMac] + "']");
      for(nro=0; nro<elements.length; nro++) {
        elements[nro].classList.add("source");
      }
      
      if (packet.targetMac === "ff:ff:ff:ff:ff:ff") {
        elements = analizer.graph.querySelectorAll(".node[data-broad*='" + packet.sourceIp + "'], .network[data-broad*='" + packet.sourceIp + "'] .node");
      } else {
        elements = analizer.graph.querySelectorAll("[data-ip*='" + analizer.topologyTable.indexMac[packet.targetMac] + "']");
      }
      for(nro=0; nro<elements.length; nro++) {
        elements[nro].classList.add("target");
      }
      
      updateAutoplay();
    }
    
    function updateAutoplay() {
      var autoplay = analizer.history.querySelector("#autoplay").checked;
      if (autoplay) {
        setTimeout(function(){
          var autoplay = analizer.history.querySelector("#autoplay").checked;
          if (!autoplay) {
            return;
          }
          
          var current = analizer.history.querySelector("input[type='radio'][name='current-packet']:checked"),
              currentRow = current.parentNode.parentNode;
              
          do {
            currentRow = currentRow.nextElementSibling;
          } while (currentRow.nextElementSibling && currentRow.nextElementSibling.classList.contains("hide"));
          
          if (currentRow !== current.parentNode.parentNode) {
            currentRow.querySelector("input[type='radio'][name='current-packet']").checked = true;
          }
          
          updateCurrentPacket();
        }, 3000);
      }
    }

    // Filter history:
    function updateFilters() {
      var protocols = analizer.protocols.querySelectorAll("input[type='checkbox']"),
          nodes = analizer.graph.querySelectorAll(".node input[type='checkbox']"),
          history = analizer.history.querySelectorAll("tbody > tr"),
          filter = {
            protocols: {},
            nodes: {}
          };

      for (var nro=protocols.length-1; nro>=0; nro--) {
        if (protocols[nro].checked) {
          filter.protocols[protocols[nro].id.replace("protocol-", "")] = true;
        }
      }

      for (var nro=nodes.length-1; nro>=0; nro--) {
        if (nodes[nro].checked) {
          filter.nodes[nodes[nro].id] = true;
        }
      }

      for (var nro=analizer.capture.traffic.length-1; nro>=0; nro--) {
        var packet = analizer.capture.traffic[nro],
            protocol = packet.protocol.lastIndexOf(":") !== -1 ? packet.protocol.substr(packet.protocol.lastIndexOf(":") + 1) : packet.protocol;

        if (filter.protocols[protocol] && // Has a valid protocol
            (
              // Has a valid sender node
              filter.nodes[analizer.topologyTable.interfaces[packet.sourceMac].id] ||
              // Has a valid target node
              (packet.targetMac !== "ff:ff:ff:ff:ff:ff" && filter.nodes[analizer.topologyTable.interfaces[packet.targetMac].id]) ||
              // Has a target node of broadcast
              (packet.targetMac === "ff:ff:ff:ff:ff:ff" && (function(){
                  for (var mac in analizer.topologyTable.interfaces) {
                    var iFace = analizer.topologyTable.interfaces[mac];
                    if (!filter.nodes[iFace.id]) {
                      continue;
                    }

                    if (iFace.broad.map(function(ip) { return analizer.topologyTable.indexIp[ip]; }).indexOf(packet.sourceMac) !== -1) {
                      return true;
                    }
                  }

                  return false;
                })()
              )
            )
           ) {
          history[nro].classList.remove("hide");
        } else {
          history[nro].classList.add("hide");
        }
      }
    }

    // Add filter behavior to protocol table:
    var filters = analizer.protocols.querySelectorAll("input[type='checkbox']");
    for (var nro=filters.length-1; nro>=0; nro--) {
      filters[nro].addEventListener("change", updateFilters);
    }

    // Add filter behavior to nodes graph:
    filters = analizer.graph.querySelectorAll(".node input[type='checkbox']");
    for (var nro=filters.length-1; nro>=0; nro--) {
      filters[nro].addEventListener("change", updateFilters);
    }

    // Add filter behavior to nodes graph:
    var packets = analizer.history.querySelectorAll("input[type='radio']");
    for (var nro=packets.length-1; nro>=0; nro--) {
      packets[nro].addEventListener("change", updateCurrentPacket);
    }

    analizer.history.querySelector("#autoplay").addEventListener("change", updateAutoplay);
    
    updateFilters();
    updateCurrentPacket();
  }

  /*/ Parse individual packet. /*/
  TyrAnalizer.parsePacket = function parsePacket(packet) {
    var info = {};
    info.protocol = packet._source.layers.frame["frame.protocols"];
    info.size = packet._source.layers.frame["frame.len"];
    info.overhead = {};

    // Protocol alias
    if (info.protocol.indexOf("http:data-text-lines") !== -1) {
      info.protocol = info.protocol.replace("http:data-text-lines", "http");
    }

    if (info.protocol.indexOf("eth:ethertype") !== -1) {
      info.protocol = info.protocol.replace("eth:ethertype", "eth");
    }

    // Copy of protocol stack
    info.protocolsStack = info.protocol;

    if (packet._source.layers.eth) {
      // It has Ethernet info
      info.sourceMac = packet._source.layers.eth["eth.src"];
      info.targetMac = packet._source.layers.eth["eth.dst"];
      info.overhead.eth = 14; // Header length in bytes
    }

    if (packet._source.layers.ip) {
      // It has IP info
      info.sourceIp = packet._source.layers.ip["ip.src"];
      info.targetIp = packet._source.layers.ip["ip.dst"];
      info.overhead.ip = 20; // Header length in bytes
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

      info.overhead.tcp = 20; // Header length in bytes
    }

    if (packet._source.layers.udp) {
      // It has UDP info
      info.sourcePort = packet._source.layers.udp["udp.srcport"];
      info.targetPort = packet._source.layers.udp["udp.dstport"];

      info.overhead.udp = 16; // Header length in bytes
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
              console.warn("This packet of http module is not parsed: ", packet);
            }
            break;
          case "dns":
            if (packet.answer || packet.aNameservers || packet.aRecords) {
              message = "El <em>" + topology.interfaces[packet.sourceMac].name  + "</em> contesta a <em>" + topology.interfaces[packet.targetMac].name  + "</em>:";
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
          default:
            console.warn("This packet is not parsed: ", packet);
            break;
        }

        var totalPercent = 0,
            totalSize = 0,
            details = packet.protocolsStack.split(":").map(function(protocol) {
                        packet.overhead[protocol] || (packet.overhead[protocol] = 0);
                        packet.overhead[protocol] = Number(packet.overhead[protocol]);

                        var percent = Math.round(packet.overhead[protocol] / packet.size * 10) / 10;
                        totalPercent += percent;
                        totalSize += packet.overhead[protocol];

                        return "<span class=\"" + protocol + "\">" + protocol + "<br><span>" + packet.overhead[protocol] + "B<br>(" + percent + "%)</span></span>";
                      })
                      .join("");

        message +=  "<div class=\"overhead\">" +
                      "<strong>Overhead de "+totalSize+"B ("+totalPercent+"%) en paquete de " + packet.size + "B:</strong>" +
                      "<div>" + details + "</div>" +
                    "</div>";

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