//
//  ContentView.swift
//  iOS-microbench
//
//  Created by Junjie on 12/09/2023.
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
        }
        .onAppear() {
            test_entry();
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
