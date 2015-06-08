/*/
 * @author Nehuen Prados <nehuensd@gmail.com>
 * @date 07/06/2015
 * @version 1.0
 * @licence Public Domain
/*/
WiresharkTyrAnalizer = function(capture_path) {
	this.parse_ready = false;
	this.callbacks = { };
	this.load_capture_file(capture_path, this.parse);
}

/*/
 * Prototype default values.
 * @since 1.0
/*/
WiresharkTyrAnalizer.prototype = {
	"animation_delay" : 4000,
	"traffic" : [],
	"i18n" : {
		"arp" : {
			"who_has" : "¿Quien tiene esta IP? <strong>{IP}</strong>",
			"i_has" : "La tengo yo: <em>{MAC}</em>",
		},
		"tcp" : {
			"syn" : "Quiero abrir una conexion en el sentido: <strong>{SOURCE} → {DESTINATION}</strong>",
			"syn_ack" : "Acepto tu conexion y quiero abrir una en el sentido: <strong>{SOURCE} → {DESTINATION}</strong> ",
			"ack" : "Ok",
			"ooo" : "<strong class=\"fail\">¡El paquete llego fuera de orden!</strong>",
			"retransmission" : "<strong class=\"fail\">Retransmisión de paquete</strong>"
		},
		"fc" : {
			"fc" : "<strong class=\"fail\">¡Uno o mas mensajes fueron dañados y nadie los entendio!</strong>",
		}
	}
}

/*/
 * Load a Wireshark .txt capture file from the path.
 * @since 1.0
/*/
WiresharkTyrAnalizer.prototype.load_capture_file = function(capture_path, callback) {
	var request = new XMLHttpRequest();
    request.onreadystatechange = function() {
        if (request.readyState == 4 && request.status == 200) {
            callback.bind(this)(request.responseText);
        }
    }.bind(this);
    request.open("GET", capture_path, true);
    request.send();
}

/*/
 * Parse a Wireshark .txt capture.
 * @since 1.0
/*/
WiresharkTyrAnalizer.prototype.parse = function(capture) {
	var line, current_traffic, next_is_info;
	capture = capture.split("\n");

	for (line=0; line<capture.length; line++) {
		// Si es la primer linea de un nuevo trafico.
		if (capture[line].indexOf("No.     ") === 0) {
			if(current_traffic)
				this.traffic.push(current_traffic);
			
			next_is_info = true;
			current_traffic = {
				"nro" : null,
				"time" : null,
				"source" : null,
				"destination" : null,
				"protocol" : null,
				"length" : null,
				"info" : null,
				"other" : [],
			};
		} else if(next_is_info) {
			next_is_info = false;
			current_traffic.nro = capture[line].substring(0, 7).trim()*1;
			current_traffic.time = capture[line].substring(7, 22).trim()*1;
			current_traffic.source = capture[line].substring(22, 45).trim();
			current_traffic.destination = capture[line].substring(45, 67).trim();
			current_traffic.protocol = capture[line].substring(67, 76).trim();
			current_traffic.length = capture[line].substring(76, 83).trim()*1;
			current_traffic.info = capture[line].substring(83).trim();
		} else {
			current_traffic.other.push(capture[line]);
		}
	}

	this.parse_ready = true;
	if(this.callbacks.parse_ready)
		this.callbacks.parse_ready();
}

/*/
 * Render a HTML table with capture info.
 * @since 1.0
/*/
WiresharkTyrAnalizer.prototype.renderTable = function(table, columns, callback) {
	// Si el parsing no esta listo, esperar hasta que lo este.
	if(!this.parse_ready) {
		this.callbacks.parse_ready = this.renderTable.bind(this, table, columns, callback);
		return;
	}

	var thead = document.createElement("thead"),
		tbody = document.createElement("tbody"),
		row,
		cell,
		column;
	table.appendChild(thead);
	table.appendChild(tbody);

	row = document.createElement("tr");
	thead.appendChild(row);
	for(column in columns) {
		cell = document.createElement("th");
		cell.innerHTML = columns[column];
		row.appendChild(cell);
	}
	this.each(0, tbody, columns, callback);	
}

WiresharkTyrAnalizer.prototype.each = function(line, tbody, columns, callback) {
	if(line >= this.traffic.length)
		return;
	
	callback || (callback = this.each.bind(this));
	
	/*/
	 * Now, parse the information for organization.
	/*/
	var current_traffic = {}, prop;
	for(prop in this.traffic[line])
		current_traffic[prop] = this.traffic[line][prop];
	
	var info = current_traffic.other[2].split("(");
	info.mac_source = info[1].substring(0, info[1].indexOf(")"));
	info.mac_destination = info[2].substring(0, info[2].indexOf(")"));
	switch(current_traffic.protocol) {
		case "ARP" :
			if(current_traffic.destination == "Broadcast") {
				var split = current_traffic.info.split("?  Tell ");
				
				current_traffic.source = "<strong>" + split[1] + "</strong>" +
										"<em>" + info.mac_source + "</em>";
				current_traffic.info = this.i18n.arp.who_has.replace("{IP}", split[0].substring(8));
	
				current_traffic.destination = "<strong>Broadcast</strong>" +
											"<em>" + info.mac_destination + "</em>";
			} else {
				var split = current_traffic.info.split(" is at ");
				current_traffic.source = "<strong>" + split[0] + "</strong>" +
										"<em>" + split[1] + "</em>";
				current_traffic.info = this.i18n.arp.i_has.replace("{MAC}", split[1]);
	
				current_traffic.destination = "<em>" + info.mac_destination + "</em>";
			}
		break;
		case "TCP" :		
			
			if(current_traffic.info.indexOf("[TCP Out-Of-Order]") !== -1) {
				current_traffic.info = this.i18n.tcp.ooo;				
			} else if(current_traffic.info.indexOf("[TCP Retransmission]") !== -1) {
				current_traffic.info = this.i18n.tcp.retransmission;				
			} else if(current_traffic.info.indexOf("[SYN]") !== -1) {
				current_traffic.info = this.i18n.tcp.syn.replace("{SOURCE}", current_traffic.source)
														.replace("{DESTINATION}", current_traffic.destination);
			} else if(current_traffic.info.indexOf("[SYN, ACK]") !== -1) {
				current_traffic.info = this.i18n.tcp.syn_ack.replace("{SOURCE}", current_traffic.source)
															.replace("{DESTINATION}", current_traffic.destination);
			}  else if(current_traffic.info.indexOf("[ACK]") !== -1) {
				current_traffic.info = this.i18n.tcp.ack;
			} 
			current_traffic.source = "<strong>" + current_traffic.source + "</strong>" +
									"<em>" + info.mac_source + "</em>";
			current_traffic.destination = "<strong>" + current_traffic.destination + "</strong>" +
										"<em>" + info.mac_destination + "</em>";
		break;
		case "TLSV1.2" :
			if(current_traffic.info.indexOf("[TCP Out-Of-Order]") !== -1) {
				current_traffic.info = this.i18n.tcp.ooo;				
			} else if(current_traffic.info.indexOf("[TCP Retransmission]") !== -1) {
				current_traffic.info = this.i18n.tcp.retransmission;				
			}
			current_traffic.source = "<strong>" + current_traffic.source + "</strong>" +
									"<em>" + info.mac_source + "</em>";
			current_traffic.destination = "<strong>" + current_traffic.destination + "</strong>" +
										"<em>" + info.mac_destination + "</em>";
		break;
		case "FC" :		
			current_traffic.info = this.i18n.fc.fc;
			current_traffic.source = "----";
			current_traffic.destination = "----";
		break;
		case "HTTP" :		
			current_traffic.source = "<strong>" + current_traffic.source + "</strong>" +
									"<em>" + info.mac_source + "</em>";
			current_traffic.destination = "<strong>" + current_traffic.destination + "</strong>" +
										"<em>" + info.mac_destination + "</em>";
		break;
	}
	
	var row = document.createElement("tr"),
	column, cell;
	
	tbody.appendChild(row);
	for(column in columns) {
		cell = document.createElement("td");
		cell.innerHTML = current_traffic[column];
		row.appendChild(cell);
	}
	
	callback(line+1, tbody, columns, null, [current_traffic, this.traffic[line]]);
}

/*/
 * Render a HTML table with capture info.
 * @since 1.0
/*/
WiresharkTyrAnalizer.prototype.timelineRender = function(messages, table, columns) {
	this.renderTable(table, columns, this.render.bind(this, messages));
	
}
WiresharkTyrAnalizer.prototype.render = function (messages, line, tbody, columns, callback, current_traffic) {
	var elements, nro, edit = current_traffic[0];
	current_traffic = current_traffic[1];
	
	elements = document.querySelectorAll('.source');
	for(nro=0; nro<elements.length; nro++)
		elements[nro].classList.remove("source");
	
	elements = document.querySelectorAll('.destination');
	for(nro=0; nro<elements.length; nro++)
		elements[nro].classList.remove("destination");
			
	var info = current_traffic.other[2].split("(");
	info.mac_source = info[1].substring(0, info[1].indexOf(")"));
	info.mac_destination = info[2].substring(0, info[2].indexOf(")"));
		
	elements = document.querySelectorAll('div[data-macs*="' + info.mac_destination + '"]');
	for(nro=0; nro<elements.length; nro++)
		elements[nro].classList.add("destination");
	
	elements = document.querySelectorAll('div[data-macs*="' + info.mac_source + '"]');
	for(nro=0; nro<elements.length; nro++)
		elements[nro].classList.add("source");
	
	if(current_traffic.destination == "Broadcast") {
		var broad;
		for(nro=0; nro<elements.length; nro++)
		{
			broad = document.querySelectorAll('.red[data-broad*="' + info.mac_source + '"] div.node:not([data-macs*="' + info.mac_source + '"]), .red[data-broad*="' + info.mac_source + '"] div.cloud');
			for(nro=0; nro<broad.length; nro++)
				broad[nro].classList.add("destination");			
		}			
	}	
	
	messages.querySelector('.mnro').innerHTML = edit.nro;
	messages.querySelector('.msource').innerHTML = edit.source;
	messages.querySelector('.mdestination').innerHTML = edit.destination;
	messages.querySelector('.mprotocol').innerHTML = edit.protocol;
	messages.querySelector('.minfo').innerHTML = current_traffic.info;
	
	setTimeout(this.each.bind(this, line, tbody, columns, this.render.bind(this, messages)), this.animation_delay);
};